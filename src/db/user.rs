use std::str::FromStr;

use async_trait::async_trait;
use bcr_ebill_core::NodeId;
use bitcoin::secp256k1::SecretKey;
use tokio_postgres::Row;

use crate::db::PostgresStore;

#[derive(Clone, Debug)]
pub struct User {
    pub node_id: NodeId,
    pub secret_key: SecretKey,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn get_by_node_id(&self, node_id: &NodeId) -> Result<Option<User>, anyhow::Error>;
}

#[async_trait]
impl UserStore for PostgresStore {
    async fn get_by_node_id(&self, node_id: &NodeId) -> Result<Option<User>, anyhow::Error> {
        let row = self
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT node_id, secret_key FROM users WHERE node_id = $1",
                &[&node_id.to_string()],
            )
            .await?;
        match row {
            Some(row) => {
                let user = row_to_user(&row)?;
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }
}

fn row_to_user(row: &Row) -> Result<User, anyhow::Error> {
    let node_id_str: String = row.get(0);
    let secret_key_str: String = row.get(1);

    Ok(User {
        node_id: NodeId::from_str(&node_id_str)?,
        secret_key: SecretKey::from_str(&secret_key_str)?,
    })
}
