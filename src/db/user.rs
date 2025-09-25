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
    pub name: String,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn get_by_node_id(&self, node_id: &NodeId) -> Result<Option<User>, anyhow::Error>;
    async fn get_by_key(
        &self,
        node_id: &NodeId,
        secret_key: &SecretKey,
    ) -> Result<Option<User>, anyhow::Error>;
    async fn create_user(
        &self,
        name: &str,
        node_id: &NodeId,
        secret_key: &SecretKey,
    ) -> Result<(), anyhow::Error>;
}

#[async_trait]
impl UserStore for PostgresStore {
    async fn get_by_node_id(&self, node_id: &NodeId) -> Result<Option<User>, anyhow::Error> {
        let row = self
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT node_id, secret_key, name FROM users WHERE node_id = $1",
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

    async fn get_by_key(
        &self,
        node_id: &NodeId,
        secret_key: &SecretKey,
    ) -> Result<Option<User>, anyhow::Error> {
        let row = self
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT node_id, secret_key, name FROM users WHERE node_id = $1 AND secret_key = $2",
                &[&node_id.to_string(), &secret_key.display_secret().to_string()],
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

    async fn create_user(
        &self,
        name: &str,
        node_id: &NodeId,
        secret_key: &SecretKey,
    ) -> Result<(), anyhow::Error> {
        self.pool
            .get()
            .await?
            .execute(
                r#"INSERT INTO users
                        (node_id, secret_key, name)
                    VALUES
                        ($1, $2, $3)
                "#,
                &[
                    &node_id.to_string(),
                    &secret_key.display_secret().to_string(),
                    &name,
                ],
            )
            .await?;
        Ok(())
    }
}

fn row_to_user(row: &Row) -> Result<User, anyhow::Error> {
    let node_id_str: String = row.get(0);
    let secret_key_str: String = row.get(1);
    let name: String = row.get(2);

    Ok(User {
        node_id: NodeId::from_str(&node_id_str)?,
        secret_key: SecretKey::from_str(&secret_key_str)?,
        name,
    })
}
