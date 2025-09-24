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
                created_at TIMESTAMPTZ DEFAULT (NOW() AT TIME ZONE 'UTC')
            )
        "#;
        self.pool.get().await?.execute(qry, &[]).await?;

        // TODO: remove hard-coded test user once we have user management
        let insert_test_user_qry = r#"
            INSERT INTO users
                (node_id, secret_key)
                VALUES
                ('bitcrt02295fb5f4eeb2f21e01eaf3a2d9a3be10f39db870d28f02146130317973a40ac0', 'd1ff7427912d3b81743d3b67ffa1e65df2156d3dab257316cbc8d0f35eeeabe9') ON CONFLICT DO NOTHING
        "#;
        self.pool
            .get()
            .await?
            .execute(insert_test_user_qry, &[])
            .await?;

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
