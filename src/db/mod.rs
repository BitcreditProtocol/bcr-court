use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

pub mod shared_bill;
pub mod user;

pub struct PostgresStore {
    pub pool: Pool,
}

impl PostgresStore {
    pub async fn new(conn_str: &str) -> Result<Self, anyhow::Error> {
        let cfg: tokio_postgres::Config = conn_str.parse()?;
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let pool = Pool::builder(Manager::from_config(cfg, NoTls, mgr_config))
            .max_size(16)
            .build()?;

        Ok(Self { pool })
    }

    pub async fn init(&self) -> Result<(), anyhow::Error> {
        // Users store (insecure and temporary for now)
        let qry = r#"
            CREATE TABLE IF NOT EXISTS users (
                node_id TEXT PRIMARY KEY,
                secret_key TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT (NOW() AT TIME ZONE 'UTC')
            )
        "#;
        self.pool.get().await?.execute(qry, &[]).await?;

        // Shared Bill Store
        let qry = r#"
            CREATE TABLE IF NOT EXISTS shared_bill (
                id UUID PRIMARY KEY,
                bill_id TEXT NOT NULL,
                plaintext_chain TEXT NOT NULL,
                file_urls TEXT[] NOT NULL DEFAULT '{}',
                hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                receiver_node_id TEXT NOT NULL,
                sender_node_id TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT (NOW() AT TIME ZONE 'UTC')
            )
        "#;

        self.pool.get().await?.execute(qry, &[]).await?;
        Ok(())
    }
}
