use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Internal Server Error")]
    Internal,
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("Not Found: {0}")]
    NotFound(String),
}
