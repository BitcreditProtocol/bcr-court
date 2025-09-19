use axum::{Router, response::IntoResponse, routing::get};
use tower_http::services::ServeDir;

use crate::{
    Config, Ctx,
    web::templates::{HomeTemplate, HtmlTemplate},
};

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;

mod templates;

pub fn router(ctx: Ctx, _cfg: &Config) -> Router {
    let web = Router::new()
        .nest_service(
            "/static",
            ServeDir::new(format!("{}/static", env!("CARGO_MANIFEST_DIR"))),
        )
        .route("/health", get(health))
        .route("/", get(home));
    Router::new().merge(web).with_state(ctx)
}

async fn health() -> Result<&'static str> {
    Ok("OK")
}

#[tracing::instrument(level = tracing::Level::DEBUG)]
pub async fn home() -> Result<impl IntoResponse> {
    Ok(HtmlTemplate(HomeTemplate {}))
}
