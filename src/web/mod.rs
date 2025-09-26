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
use tower_sessions::{
    Expiry, SessionManagerLayer,
    cookie::{SameSite, time::Duration},
};

use crate::{
    Config, Ctx,
    web::templates::{Auth, HomeTemplate, HtmlTemplate},
};

mod bill;
mod csrf;
mod error;
pub mod rate_limit;
pub mod session;
mod templates;
mod user;

pub type Result<T> = std::result::Result<T, error::Error>;

pub const SESSION_EXPIRATION_SEC: i64 = 60 * 30; // 30 min
pub const CSRF_TOKEN: &str = "csrf_token";
pub const NODE_ID: &str = "node_id";

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

pub fn router(ctx: Ctx, cfg: &Config) -> Router {
    let sessions = SessionManagerLayer::new(ctx.session_store.clone())
        .with_secure(cfg.cookie_secure)
        .with_domain(cfg.domain.clone())
        .with_same_site(SameSite::Strict)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(
            SESSION_EXPIRATION_SEC,
        )))
        .with_http_only(true);

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
        .route("/shared_bills", get(bill::ssr::list))
        .route("/shared_bill/{id}", get(bill::ssr::detail))
        .route("/user/create_keyset", get(user::create_keyset))
        .route("/user/do_create_keyset", post(user::do_create_keyset))
        .route("/user/login", get(user::login))
        .route("/user/do_login", post(user::do_login))
        .route("/user/logout", get(user::logout))
        .route(
            "/v1/bill/receive",
            post(bill::rest::receive_shared_bill).layer(cors),
        )
        .layer(sessions);
    Router::new().merge(web).with_state(ctx)
}

async fn health() -> Result<&'static str> {
    Ok("OK")
}

#[tracing::instrument(level = tracing::Level::DEBUG)]
pub async fn home(auth: Auth) -> Result<impl IntoResponse> {
    Ok(HtmlTemplate(HomeTemplate { auth }))
}
