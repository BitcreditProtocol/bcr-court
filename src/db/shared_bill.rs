use async_trait::async_trait;
use bcr_ebill_core::{NodeId, bill::BillId};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::PostgresStore;

#[derive(Clone, Debug)]
pub struct SharedBill {
    pub id: Uuid,
    pub bill_id: BillId,
    pub plaintext_chain: String, // base58 encoded, encrypted BillBlockPlaintextWrapper of the bill
    pub file_urls: Vec<url::Url>,
    pub hash: String,
    pub signature: String,
    pub receiver_node_id: NodeId,
    pub sender_node_id: NodeId,
    pub created_at: DateTime<Utc>,
}

impl SharedBill {
    pub fn new(
        bill_id: BillId,
        plaintext_chain: String,
        file_urls: Vec<url::Url>,
        hash: String,
        signature: String,
        receiver_node_id: NodeId,
        sender_node_id: NodeId,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            bill_id,
            plaintext_chain,
            file_urls,
            hash,
            signature,
            receiver_node_id,
            sender_node_id,
            created_at: Utc::now(),
        }
    }
}

#[async_trait]
pub trait SharedBillStore: Send + Sync {
    async fn add_shared_bill(&self, shared_bill: &SharedBill) -> Result<(), anyhow::Error>;
}

#[async_trait]
impl SharedBillStore for PostgresStore {
    async fn add_shared_bill(&self, shared_bill: &SharedBill) -> Result<(), anyhow::Error> {
        self.pool
            .get()
            .await?
            .execute(
                r#"INSERT INTO shared_bill
                        (id, bill_id, plaintext_chain, file_urls, hash, signature, receiver_node_id, sender_node_id, created_at)
                    VALUES
                        ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
                &[
                &shared_bill.id,
                &shared_bill.bill_id.to_string(),
                &shared_bill.plaintext_chain,
                &shared_bill.file_urls.iter().map(|u| u.to_string()).collect::<Vec<String>>(),
                &shared_bill.hash,
                &shared_bill.signature,
                &shared_bill.receiver_node_id.to_string(),
                &shared_bill.sender_node_id.to_string(),
                &shared_bill.created_at
                ],
            )
            .await?;
        Ok(())
    }
}
