use std::str::FromStr;

use async_trait::async_trait;
use bcr_ebill_core::{NodeId, bill::BillId};
use chrono::{DateTime, Utc};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::PostgresStore;

#[derive(Clone, Debug)]
pub struct LightSharedBill {
    pub id: Uuid,
    pub bill_id: BillId,
    pub receiver_node_id: NodeId,
    pub sender_node_id: NodeId,
    pub created_at: DateTime<Utc>,
}

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
    async fn get_shared_bill_list_for_receiver(
        &self,
        receiver_node_id: &NodeId,
    ) -> Result<Vec<LightSharedBill>, anyhow::Error>;
    async fn get_shared_bill_by_id_for_receiver(
        &self,
        id: &Uuid,
        receiver_node_id: &NodeId,
    ) -> Result<Option<SharedBill>, anyhow::Error>;
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

    async fn get_shared_bill_list_for_receiver(
        &self,
        receiver_node_id: &NodeId,
    ) -> Result<Vec<LightSharedBill>, anyhow::Error> {
        let rows = self.pool.get().await?.query("SELECT id, bill_id, receiver_node_id, sender_node_id, created_at FROM shared_bill WHERE receiver_node_id = $1 ORDER BY created_at DESC", &[&receiver_node_id.to_string()]).await?;

        let res: Result<Vec<LightSharedBill>, anyhow::Error> =
            rows.iter().map(row_to_light_shared_bill).collect();

        res
    }

    async fn get_shared_bill_by_id_for_receiver(
        &self,
        id: &Uuid,
        receiver_node_id: &NodeId,
    ) -> Result<Option<SharedBill>, anyhow::Error> {
        let row = self
            .pool
            .get()
            .await?
            .query_opt("SELECT id, bill_id, plaintext_chain, file_urls, hash, signature, receiver_node_id, sender_node_id, created_at FROM shared_bill WHERE id = $1 AND receiver_node_id = $2", &[&id, &receiver_node_id.to_string()])
            .await?;
        let shared_bill = row.map(|r| row_to_shared_bill(&r));

        match shared_bill {
            Some(sb) => Ok(Some(sb?)),
            None => Ok(None),
        }
    }
}

fn row_to_light_shared_bill(row: &Row) -> Result<LightSharedBill, anyhow::Error> {
    let id: Uuid = row.get(0);
    let bill_id: BillId = BillId::from_str(&row.get::<usize, String>(1))?;
    let receiver_node_id: NodeId = NodeId::from_str(&row.get::<usize, String>(2))?;
    let sender_node_id: NodeId = NodeId::from_str(&row.get::<usize, String>(3))?;
    let created_at: DateTime<Utc> = row.get(4);

    Ok(LightSharedBill {
        id,
        bill_id,
        receiver_node_id,
        sender_node_id,
        created_at,
    })
}

fn row_to_shared_bill(row: &Row) -> Result<SharedBill, anyhow::Error> {
    let id: Uuid = row.get(0);
    let bill_id: BillId = BillId::from_str(&row.get::<usize, String>(1))?;
    let plaintext_chain: String = row.get(2);
    let file_urls: Vec<String> = row.get(3);
    let hash: String = row.get(4);
    let signature: String = row.get(5);
    let receiver_node_id: NodeId = NodeId::from_str(&row.get::<usize, String>(6))?;
    let sender_node_id: NodeId = NodeId::from_str(&row.get::<usize, String>(7))?;
    let created_at: DateTime<Utc> = row.get(8);

    let mut parsed_file_urls: Vec<url::Url> = Vec::with_capacity(file_urls.len());
    for file_url in file_urls.iter() {
        parsed_file_urls.push(url::Url::parse(file_url)?);
    }

    Ok(SharedBill {
        id,
        bill_id,
        plaintext_chain,
        file_urls: parsed_file_urls,
        hash,
        signature,
        receiver_node_id,
        sender_node_id,
        created_at,
    })
}
