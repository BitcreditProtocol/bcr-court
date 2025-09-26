use askama::Template;
use axum::{
    RequestPartsExt,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::web::{
    NODE_ID,
    bill::data::{BillForDetail, BillForList},
};

use super::error::Error;

pub struct HtmlTemplate<T>(pub T);

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub auth: Auth,
    pub error: String,
}

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!("Error rendering template: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error rendering template",
                )
                    .into_response()
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Auth {
    pub user: Option<AuthUser>,
}

impl Auth {
    pub fn no_user() -> Self {
        Self { user: None }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthUser {
    pub node_id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "home.html")]
pub struct HomeTemplate {
    pub auth: Auth,
}

#[derive(Template)]
#[template(path = "bills.html")]
pub struct BillsTemplate {
    pub auth: Auth,
    pub receiver: String,
    pub bills: Vec<BillForList>,
}

#[derive(Template)]
#[template(path = "bill.html")]
pub struct BillDetailTemplate {
    pub auth: Auth,
    pub bill: BillForDetail,
    pub bill_plaintext_chain: Vec<String>,
}

#[derive(Template)]
#[template(path = "user_create_keyset.html")]
pub struct UserCreateKeysetTemplate {
    pub auth: Auth,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "user_keyset.html")]
pub struct UserKeysetTemplate {
    pub auth: Auth,
    pub name: String,
    pub node_id: String,
    pub seed_phrase: String,
}

#[derive(Template)]
#[template(path = "user_login.html")]
pub struct UserLoginTemplate {
    pub auth: Auth,
    pub csrf_token: String,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let response = match self {
            Error::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Internal Server Error"),
            ),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, String::from("Unauthorized")),
            Error::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                String::from("Too Many Requests"),
            ),
            Error::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Error::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        (
            response.0,
            HtmlTemplate(ErrorTemplate {
                error: response.1,
                auth: Auth::default(),
            }),
        )
            .into_response()
    }
}

impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extract::<Session>().await {
            Ok(session) => {
                if let Ok(Some(user)) = session.get::<AuthUser>(NODE_ID).await {
                    Ok(Auth { user: Some(user) })
                } else {
                    Ok(Auth::no_user())
                }
            }
            Err(e) => {
                tracing::error!("couldn't extract session: {e:?}");
                Ok(Auth::no_user())
            }
        }
    }
}
