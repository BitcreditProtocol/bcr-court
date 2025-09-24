use std::str::FromStr;

use anyhow::anyhow;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use bcr_ebill_core::NodeId;
use chrono::{DateTime, Utc};
use tracing::error;
use uuid::Uuid;

use crate::{
    Ctx,
    web::{
        Result,
        bill::{
            data::{BillForDetail, BillForList},
            rest::decrypt_bill,
        },
        error::Error,
        templates::{BillDetailTemplate, BillsTemplate, HtmlTemplate},
    },
};

#[tracing::instrument(level = tracing::Level::DEBUG, skip(ctx))]
pub async fn list(State(ctx): State<Ctx>) -> Result<impl IntoResponse> {
    // TODO: replace hard-coded node-id, get from session once user mgmt is implemented
    let node_id = NodeId::from_str(
        "bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0",
    )
    .expect("valid node_id");

    let bills = ctx
        .shared_bill_store
        .get_shared_bill_list_for_receiver(&node_id)
        .await
        .map_err(|e| {
            error!("Error fetching shared bills for {node_id}: {e}");
            Error::Internal
        })?;
    Ok(HtmlTemplate(BillsTemplate {
        receiver: node_id.to_string(),
        bills: bills
            .into_iter()
            .map(|b| BillForList {
                id: b.id.to_string(),
                bill_id: b.bill_id.to_string(),
                sender_node_id: b.sender_node_id.to_string(),
                created_at: format_date(&b.created_at),
            })
            .collect(),
    }))
}

#[tracing::instrument(level = tracing::Level::DEBUG, skip(ctx))]
pub async fn detail(State(ctx): State<Ctx>, Path(id): Path<String>) -> Result<impl IntoResponse> {
    // TODO: replace hard-coded node-id, get from session once user mgmt is implemented
    let node_id = NodeId::from_str(
        "bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0",
    )
    .expect("valid node_id");
    let user = match ctx.user_store.get_by_node_id(&node_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(Error::NotFound("user not found".to_string())),
        Err(e) => {
            error!("Error fetching user {node_id}: {e}");
            return Err(Error::Internal);
        }
    };

    let parsed_id = Uuid::from_str(&id).map_err(|_| Error::BadRequest("invalid id".to_string()))?;

    let bill = match ctx
        .shared_bill_store
        .get_shared_bill_by_id_for_receiver(&parsed_id, &node_id)
        .await
    {
        Ok(Some(bill)) => bill,
        Ok(None) => return Err(Error::NotFound("bill not found".to_string())),
        Err(e) => {
            error!("Error fetching bill {id}: {e}");
            return Err(Error::Internal);
        }
    };

    let bill_id = bill.bill_id;
    let secret_key = user.secret_key;
    let decrypted_bill = match decrypt_bill(&bill.plaintext_chain, &bill.hash, &secret_key) {
        Ok(bill) => bill,
        Err(e) => {
            error!("Error decrypting shared bill {bill_id}: {e}");
            return Err(Error::Internal);
        }
    };
    let blocks_as_plaintext_json: std::result::Result<Vec<String>, anyhow::Error> = decrypted_bill
        .iter()
        .map(|block| block.to_json_text().map_err(|e| anyhow!(e)))
        .collect();

    Ok(HtmlTemplate(BillDetailTemplate {
        bill: BillForDetail {
            id: parsed_id.to_string(),
            bill_id: bill_id.to_string(),
            created_at: format_date(&bill.created_at),
            sender_node_id: bill.sender_node_id.to_string(),
            receiver_node_id: bill.receiver_node_id.to_string(),
            hash: bill.hash,
            signature: bill.signature,
        },
        bill_plaintext_chain: blocks_as_plaintext_json.map_err(|e| {
            error!("Could not create JSON chain for bill {bill_id}: {e}");
            Error::Internal
        })?,
    }))
}

fn format_date(d: &DateTime<Utc>) -> String {
    d.format("%d.%m.%Y %H:%M:%S").to_string()
}
