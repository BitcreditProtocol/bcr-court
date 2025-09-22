use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

pub mod shared_bills;

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
        // Shared Bill Store
        let qry = r#"
        SELECT 1;
        "#;

        self.pool.get().await?.execute(qry, &[]).await?;
        Ok(())
    }
}
