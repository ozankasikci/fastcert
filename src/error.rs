use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("CA root not found")]
    CARootNotFound,

    #[error("CA key missing")]
    CAKeyMissing,

    #[error("Trust store error: {0}")]
    TrustStore(String),

    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),

    #[error("Command failed: {0}")]
    CommandFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;
