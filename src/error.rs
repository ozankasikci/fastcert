use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Certificate generation error: {0}")]
    Certificate(String),

    #[error(
        "CA root directory not found. Set CAROOT environment variable or ensure default location is accessible"
    )]
    CARootNotFound,

    #[error("CA private key is missing. The CA may not have been properly initialized")]
    CAKeyMissing,

    #[error("Trust store operation failed: {0}")]
    TrustStore(String),

    #[error(
        "Invalid hostname '{0}'. Hostnames must contain only alphanumeric characters, hyphens, underscores, and dots"
    )]
    InvalidHostname(String),

    #[error("Command execution failed: {0}")]
    CommandFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;
