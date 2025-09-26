use std::collections::HashSet;

use anyhow::anyhow;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use bcr_ebill_core::{
    NodeId,
    blockchain::bill::{
        BillBlock, BillBlockchain, BillOpCode, BillToShareWithExternalParty,
        block::{
            BillAcceptBlockData, BillEndorseBlockData, BillIssueBlockData, BillMintBlockData,
            BillOfferToSellBlockData, BillRecourseBlockData, BillRejectBlockData,
            BillRejectToBuyBlockData, BillRequestRecourseBlockData, BillRequestToAcceptBlockData,
            BillRequestToPayBlockData, BillSellBlockData,
        },
        chain::BillBlockPlaintextWrapper,
    },
    util,
};
use bitcoin::{
    hashes::{Hash, sha256::Hash as Sha256},
    secp256k1::{Message, PublicKey, SECP256K1, SecretKey},
};
use borsh_derive::BorshSerialize;
use futures::StreamExt;
use serde::Deserialize;
use tracing::{error, warn};

use crate::{
    Ctx,
    db::shared_bill::SharedBill,
    web::{ErrorResp, SuccessResp, rate_limit::RealIp},
};

pub const MAX_DOCUMENT_FILE_SIZE_BYTES: usize = 1_000_000; // ~1 MB

#[derive(Debug, Deserialize, BorshSerialize)]
pub struct ReceiveBillRequest {
    pub content: BillToShareWithExternalParty,
    #[borsh(
        serialize_with = "bcr_ebill_core::util::borsh::serialize_pubkey",
        deserialize_with = "bcr_ebill_core::util::borsh::deserialize_pubkey"
    )]
    pub public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
pub struct SignedReceiveBillRequest {
    pub request: ReceiveBillRequest,
    pub signature: bitcoin::secp256k1::schnorr::Signature,
}

/// Receives a shared bill, signed by the sender, encrypted for the receiver
/// Decrypt and validate the bill, checking all signatures and files
/// And finally persist the bill in the database
#[tracing::instrument(level = tracing::Level::DEBUG, skip(ctx, req, ip))]
pub async fn receive_shared_bill(
    RealIp(ip): RealIp,
    State(ctx): State<Ctx>,
    Json(req): Json<SignedReceiveBillRequest>,
) -> impl IntoResponse {
    let ReceiveBillRequest {
        ref content,
        public_key,
    } = req.request;

    // rate limit
    let mut rate_limiter = ctx.rate_limiter.lock().await;
    let allowed = rate_limiter.check(&ip.to_string(), Some(&public_key.to_string()));
    drop(rate_limiter);
    if !allowed {
        warn!(
            "Rate limited req from {} with pub key {}",
            &ip.to_string(),
            &public_key
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResp::new("Please try again later")),
        )
            .into_response();
    }

    // check that bill is in the right network
    let bill_id = content.bill_id.clone();
    if bill_id.network() != ctx.config.bitcoin_network {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResp::new("wrong network bill")),
        )
            .into_response();
    }

    // check if receiver exists on our system
    let receiver_node_id = NodeId::new(content.receiver, ctx.config.bitcoin_network);
    let user = match ctx.user_store.get_by_node_id(&receiver_node_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResp::new("No such receiver")),
            )
                .into_response();
        }
        Err(e) => {
            error!("Error fetching receiver {}: {e}", receiver_node_id);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResp::new("internal server error")),
            )
                .into_response();
        }
    };
    let secret_key = user.secret_key;
    let decrypted_bill = match decrypt_bill(&content.data, &content.hash, &secret_key) {
        Ok(bill) => bill,
        Err(e) => {
            error!("Error decrypting shared bill {bill_id}: {e}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResp::new("bill could not be decrypted")),
            )
                .into_response();
        }
    };

    if let Err(e) = validate_bill(&decrypted_bill) {
        error!("Error validating shared bill {bill_id}: {e}");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResp::new("bill validation error")),
        )
            .into_response();
    }

    // check sender and signature
    let sender_node_id = NodeId::new(public_key, ctx.config.bitcoin_network);
    let participants = match get_participants_from_plaintext_bill(&decrypted_bill) {
        Ok(p) => p,
        Err(e) => {
            error!("Error getting bill participants from bill {bill_id}: {e}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResp::new("invalid bill participants")),
            )
                .into_response();
        }
    };

    // sender needs to be a participant of the bill
    if !participants.contains(&sender_node_id) {
        error!("Error sender {sender_node_id} is not participant of bill {bill_id}");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResp::new("sender is not part of the bill")),
        )
            .into_response();
    }

    // verify request signature of the sender
    match verify_receive_bill_request_signature(&req, &sender_node_id) {
        Ok(_) => (), // fine
        Err(e) => {
            error!("Error checking request signature for bill {bill_id}: {e}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResp::new("invalid request signature")),
            )
                .into_response();
        }
    };

    // verify shared bill signature of the sender
    match util::crypto::verify(&content.hash, &content.signature, &sender_node_id.pub_key()) {
        Ok(res) => {
            if !res {
                error!("Error invalid shared bill signature for bill {bill_id}");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResp::new("invalid shared bill signature")),
                )
                    .into_response();
            }
        }
        Err(e) => {
            error!("Error checking shared bill signature for bill {bill_id}: {e}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResp::new("invalid shared bill signature")),
            )
                .into_response();
        }
    };

    // get bill data
    let bill_data = match decrypted_bill.first() {
        Some(issue_block) => match issue_block.get_bill_data() {
            Ok(d) => d,
            Err(e) => {
                error!("Error getting bill data for bill {bill_id}: {e}");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResp::new("invalid bill data")),
                )
                    .into_response();
            }
        },
        None => {
            error!("Error getting bill data for bill {bill_id}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResp::new("invalid bill")),
            )
                .into_response();
        }
    };

    // validate files by downloading, encrypting and checking hashes
    if !content.file_urls.is_empty() {
        let bill_file_hashes: Vec<String> =
            bill_data.files.iter().map(|f| f.hash.clone()).collect();
        let mut file_hashes = Vec::with_capacity(bill_file_hashes.len());
        for file_url in content.file_urls.iter() {
            let (_, decrypted) = match do_get_encrypted_bill_file(&secret_key, file_url).await {
                Ok(d) => d,
                Err(e) => {
                    error!(
                        "Error downloading and decrypting file for {bill_id} and file {file_url}: {e}"
                    );
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResp::new("file fetching and decrypting failed")),
                    )
                        .into_response();
                }
            };
            file_hashes.push(util::sha256_hash(&decrypted));
        }
        // all of the shared file hashes have to be present on the bill
        if file_hashes.len() != bill_file_hashes.len()
            || !file_hashes.iter().all(|f| bill_file_hashes.contains(f))
        {
            error!("Error validating files for bill {bill_id}");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResp::new("file hashes don't match")),
            )
                .into_response();
        }
    }

    // persist the encrypted bill with metadata
    let shared_bill = SharedBill::new(
        bill_id.to_owned(),
        content.data.clone(),
        content.file_urls.clone(),
        content.hash.clone(),
        content.signature.clone(),
        receiver_node_id,
        sender_node_id,
    );

    if let Err(e) = ctx.shared_bill_store.add_shared_bill(&shared_bill).await {
        error!("Error persisting bill {bill_id}: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp::new("internal server error")),
        )
            .into_response();
    }

    (StatusCode::OK, Json(SuccessResp::new("Success"))).into_response()
}

pub fn decrypt_bill(
    shared_bill_data: &str,
    shared_bill_hash: &str,
    secret_key: &SecretKey,
) -> Result<Vec<BillBlockPlaintextWrapper>, anyhow::Error> {
    let decrypted =
        util::crypto::decrypt_ecies(&util::base58_decode(shared_bill_data)?, secret_key)?;
    if shared_bill_hash != util::sha256_hash(&decrypted) {
        return Err(anyhow!("Invalid Hash".to_string()));
    }
    let deserialized: Vec<BillBlockPlaintextWrapper> = borsh::from_slice(&decrypted)?;
    Ok(deserialized)
}

// Validate chain, blocks and return chain
fn validate_bill(chain: &[BillBlockPlaintextWrapper]) -> Result<BillBlockchain, anyhow::Error> {
    // validate chain
    let bill_blockchain = BillBlockchain::new_from_blocks(
        chain
            .iter()
            .map(|wrapper| wrapper.block.to_owned())
            .collect::<Vec<BillBlock>>(),
    )?;

    // validate plaintext hashes
    for block_wrapper in chain.iter() {
        if block_wrapper.block.plaintext_hash
            != util::sha256_hash(&block_wrapper.plaintext_data_bytes)
        {
            return Err(anyhow!("Plaintext hash mismatch"));
        }
    }

    Ok(bill_blockchain)
}

fn get_participants_from_plaintext_bill(
    chain: &[BillBlockPlaintextWrapper],
) -> Result<Vec<NodeId>, anyhow::Error> {
    let mut nodes = HashSet::new();
    for block_wrapper in chain.iter() {
        match block_wrapper.block.op_code {
            BillOpCode::Issue => {
                let data: BillIssueBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.drawer.node_id);
                nodes.insert(data.payee.node_id().to_owned());
                nodes.insert(data.drawee.node_id);
            }
            BillOpCode::Endorse => {
                let data: BillEndorseBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.endorsee.node_id());
                nodes.insert(data.endorser.node_id());
            }
            BillOpCode::Mint => {
                let data: BillMintBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.endorsee.node_id());
                nodes.insert(data.endorser.node_id());
            }
            BillOpCode::RequestToAccept => {
                let data: BillRequestToAcceptBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.requester.node_id());
            }
            BillOpCode::Accept => {
                let data: BillAcceptBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.accepter.node_id);
            }
            BillOpCode::RequestToPay => {
                let data: BillRequestToPayBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.requester.node_id());
            }
            BillOpCode::OfferToSell => {
                let data: BillOfferToSellBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.buyer.node_id());
                nodes.insert(data.seller.node_id());
            }
            BillOpCode::Sell => {
                let data: BillSellBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.buyer.node_id());
                nodes.insert(data.seller.node_id());
            }
            BillOpCode::RejectToAccept
            | BillOpCode::RejectToPay
            | BillOpCode::RejectToPayRecourse => {
                let data: BillRejectBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.rejecter.node_id);
            }
            BillOpCode::RejectToBuy => {
                let data: BillRejectToBuyBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.rejecter.node_id());
            }
            BillOpCode::RequestRecourse => {
                let data: BillRequestRecourseBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.recourser.node_id);
                nodes.insert(data.recoursee.node_id);
            }
            BillOpCode::Recourse => {
                let data: BillRecourseBlockData =
                    borsh::from_slice(&block_wrapper.plaintext_data_bytes)?;
                nodes.insert(data.recourser.node_id);
                nodes.insert(data.recoursee.node_id);
            }
        }
    }
    Ok(nodes.into_iter().collect())
}

// download and decrypt file from the given URL
async fn do_get_encrypted_bill_file(
    secret_key: &SecretKey,
    file_url: &url::Url,
) -> Result<(String, Vec<u8>), anyhow::Error> {
    if file_url.scheme() != "https" {
        return Err(anyhow!("Only HTTPS urls are allowed"));
    }

    // fetch the file by URL
    let resp = reqwest::get(file_url.clone()).await.map_err(|e| {
        tracing::error!("Error downloading file from {}: {e}", file_url.to_string());
        anyhow!("Could not download file")
    })?;

    // check status code
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("Could not download file"));
    }

    // check content length
    match resp.content_length() {
        Some(len) => {
            if len > MAX_DOCUMENT_FILE_SIZE_BYTES as u64 {
                return Err(anyhow!("File too large"));
            }
        }
        None => {
            return Err(anyhow!("no Content-Length set"));
        }
    };
    // stream bytes and stop if response gets too large
    let mut stream = resp.bytes_stream();
    let mut total: usize = 0;
    let mut file_bytes = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::error!("Error downloading file from {}: {e}", file_url.to_string());
            anyhow!("Could not download file")
        })?;
        total += chunk.len();
        if total > MAX_DOCUMENT_FILE_SIZE_BYTES {
            return Err(anyhow!("File too large"));
        }
        file_bytes.extend_from_slice(&chunk);
    }

    // decrypt file with private key
    let decrypted = util::crypto::decrypt_ecies(&file_bytes, secret_key).map_err(|e| {
        tracing::error!("Error decrypting file from {}: {e}", file_url.to_string());
        anyhow!("Decryption Error")
    })?;

    // detect content type and return response
    let content_type =
        detect_content_type_for_bytes(&decrypted).ok_or(anyhow!("Content Type error"))?;

    Ok((content_type, decrypted))
}

fn detect_content_type_for_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 256 {
        return None; // can't decide with so few bytes
    }
    infer::get(&bytes[..256]).map(|t| t.mime_type().to_owned())
}

fn verify_receive_bill_request_signature(
    req: &SignedReceiveBillRequest,
    sender_node_id: &NodeId,
) -> Result<(), anyhow::Error> {
    let serialized = borsh::to_vec(&req.request)?;
    let sha = Sha256::hash(&serialized);
    let msg = Message::from_digest(*sha.as_ref());

    SECP256K1.verify_schnorr(
        &req.signature,
        &msg,
        &sender_node_id.pub_key().x_only_public_key().0,
    )?;
    Ok(())
}
