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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = Error::Io(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("file not found"));
    }

    #[test]
    fn test_io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn test_certificate_error_display() {
        let err = Error::Certificate("invalid certificate data".to_string());
        assert_eq!(
            format!("{}", err),
            "Certificate generation error: invalid certificate data"
        );
    }

    #[test]
    fn test_ca_root_not_found_error() {
        let err = Error::CARootNotFound;
        let msg = format!("{}", err);
        assert!(msg.contains("CA root directory not found"));
        assert!(msg.contains("CAROOT"));
    }

    #[test]
    fn test_ca_key_missing_error() {
        let err = Error::CAKeyMissing;
        let msg = format!("{}", err);
        assert!(msg.contains("CA private key is missing"));
        assert!(msg.contains("not have been properly initialized"));
    }

    #[test]
    fn test_trust_store_error() {
        let err = Error::TrustStore("certutil command failed".to_string());
        assert_eq!(
            format!("{}", err),
            "Trust store operation failed: certutil command failed"
        );
    }

    #[test]
    fn test_invalid_hostname_error() {
        let err = Error::InvalidHostname("bad@host".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid hostname"));
        assert!(msg.contains("bad@host"));
        assert!(msg.contains("alphanumeric"));
    }

    #[test]
    fn test_command_failed_error() {
        let err = Error::CommandFailed("openssl failed with exit code 1".to_string());
        assert_eq!(
            format!("{}", err),
            "Command execution failed: openssl failed with exit code 1"
        );
    }

    #[test]
    fn test_error_debug_format() {
        let err = Error::Certificate("test error".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Certificate"));
    }

    #[test]
    fn test_result_type_ok() {
        let result: Result<i32> = Ok(42);
        assert!(result.is_ok());
        if let Ok(value) = result {
            assert_eq!(value, 42);
        }
    }

    #[test]
    fn test_result_type_err() {
        let result: Result<i32> = Err(Error::CARootNotFound);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let err = Error::Io(io_err);
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn test_certificate_error_with_special_chars() {
        let err = Error::Certificate("error with 'quotes' and \"double quotes\"".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("quotes"));
    }

    #[test]
    fn test_command_failed_multiline() {
        let err = Error::CommandFailed("line1\nline2\nline3".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("line1"));
        assert!(msg.contains("line2"));
    }
}
