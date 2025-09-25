use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Internal Server Error")]
    Internal,
    #[error("Too Many Requests")]
    TooManyRequests,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("Not Found: {0}")]
    NotFound(String),
}
