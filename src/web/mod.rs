use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Serialize;
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};

use crate::{
    Config, Ctx,
    web::templates::{HomeTemplate, HtmlTemplate},
};

mod bill;
mod error;
pub mod rate_limit;
mod templates;

pub type Result<T> = std::result::Result<T, error::Error>;

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResp {
    pub msg: String,
}

impl ErrorResp {
    pub fn new(msg: &str) -> Self {
        Self {
            msg: msg.to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SuccessResp {
    pub msg: String,
}

impl SuccessResp {
    pub fn new(msg: &str) -> Self {
        Self {
            msg: msg.to_owned(),
        }
    }
}

pub fn router(ctx: Ctx, _cfg: &Config) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let web = Router::new()
        .nest_service(
            "/static",
            ServeDir::new(format!("{}/static", env!("CARGO_MANIFEST_DIR"))),
        )
        .route("/health", get(health))
        .route("/", get(home))
        .route(
            "/v1/bill/receive",
            post(bill::receive_shared_bill).layer(cors),
        );
    Router::new().merge(web).with_state(ctx)
}

async fn health() -> Result<&'static str> {
    Ok("OK")
}

#[tracing::instrument(level = tracing::Level::DEBUG)]
pub async fn home() -> Result<impl IntoResponse> {
    Ok(HtmlTemplate(HomeTemplate {}))
}
