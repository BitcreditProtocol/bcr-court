use axum::extract::FromRef;
use config::{Environment, File};
use std::{env, net::SocketAddr, str::FromStr, sync::Arc};
use tokio::sync::Mutex;
use tower_sessions::ExpiredDeletion;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::{Layer, layer::SubscriberExt};

use crate::{
    db::{shared_bill::SharedBillStore, user::UserStore},
    web::{rate_limit::RateLimiter, session::InMemSessionStore},
};

mod db;
mod web;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Config {
    pub address: std::net::SocketAddr,
    pub domain: String,
    pub cookie_secure: bool,
    pub log_level: String,
    pub db_user: String,
    pub db_password: String,
    pub db_name: String,
    pub db_host: String,
    pub bitcoin_network: bitcoin::Network,
}

impl Config {
    pub fn db_connection_string(&self) -> String {
        let db_name = if self.db_name.is_empty() {
            "".to_string()
        } else {
            format!("/{}", self.db_name)
        };
        format!(
            "postgres://{}:{}@{}?host={}",
            self.db_user, self.db_password, db_name, self.db_host
        )
    }
}

impl Config {
    pub fn new() -> Self {
        let s = config::Config::builder()
            .add_source(File::with_name(&format!(
                "{}/config/config.toml",
                env!("CARGO_MANIFEST_DIR")
            )))
            .add_source(Environment::with_prefix("COURT").separator("__"))
            .build()
            .expect("failed to build config");

        s.try_deserialize().expect("failed to parse config")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, FromRef)]
pub struct Ctx {
    pub shared_bill_store: Arc<dyn SharedBillStore>,
    pub user_store: Arc<dyn UserStore>,
    pub config: Config,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub session_store: InMemSessionStore,
}
impl Ctx {
    pub async fn new(cfg: &Config) -> Result<Self, anyhow::Error> {
        let db = db::PostgresStore::new(&cfg.db_connection_string()).await?;
        db.init().await?;
        let store = Arc::new(db);

        let session_store = InMemSessionStore::default();

        // Delete expired sessions regularly
        let session_store_clone = session_store.clone();
        tokio::spawn(async move {
            if let Err(e) = session_store_clone
                .continuously_delete_expired(tokio::time::Duration::from_secs(60))
                .await
            {
                tracing::error!("Error deleting expired sessions: {e}");
            }
        });

        Ok(Self {
            shared_bill_store: store.clone(),
            user_store: store,
            config: cfg.to_owned(),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
            session_store,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cfg = Config::new();

    tracing_log::LogTracer::init().expect("LogTracer init");
    let level_filter = LevelFilter::from_str(&cfg.log_level).expect("log level");
    let stdout_log = tracing_subscriber::fmt::layer().with_filter(level_filter);
    let subscriber = tracing_subscriber::registry().with(stdout_log);
    tracing::subscriber::set_global_default(subscriber)
        .expect("tracing::subscriber::set_global_default");

    if let Ok(listener) = tokio::net::TcpListener::bind(&cfg.address).await {
        info!(
            "Server running at http://{} on {} with log-level={}",
            cfg.address, cfg.bitcoin_network, cfg.log_level
        );
        let ctx = Ctx::new(&cfg).await?;
        let router = web::router(ctx, &cfg);
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_handler())
        .await?;
    } else {
        error!("Failed to bind to listen address {}", &cfg.address);
    }

    Ok(())
}

async fn shutdown_handler() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("to install ctrl_c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
