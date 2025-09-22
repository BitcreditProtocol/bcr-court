use thiserror::Error;

#[allow(unused)]
#[derive(Debug, Error)]
pub enum Error {
    #[error("Unauthorized")]
    Unauthorized,
}
