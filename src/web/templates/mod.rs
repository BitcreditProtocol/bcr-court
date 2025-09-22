use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

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

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("Error: {}", self);
        let response = match self {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, String::from("Unauthorized")),
        };

        (
            response.0,
            HtmlTemplate(ErrorTemplate { error: response.1 }),
        )
            .into_response()
    }
}
