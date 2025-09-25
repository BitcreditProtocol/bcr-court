use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::web::bill::data::{BillForDetail, BillForList};

use super::error::Error;

pub struct HtmlTemplate<T>(pub T);

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
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

#[derive(Template)]
#[template(path = "home.html")]
pub struct HomeTemplate {}

#[derive(Template)]
#[template(path = "bills.html")]
pub struct BillsTemplate {
    pub receiver: String,
    pub bills: Vec<BillForList>,
}

#[derive(Template)]
#[template(path = "bill.html")]
pub struct BillDetailTemplate {
    pub bill: BillForDetail,
    pub bill_plaintext_chain: Vec<String>,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let response = match self {
            Error::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Internal Server Error"),
            ),
            Error::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Error::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        (
            response.0,
            HtmlTemplate(ErrorTemplate { error: response.1 }),
        )
            .into_response()
    }
}
