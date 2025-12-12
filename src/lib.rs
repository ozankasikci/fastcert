//! # fastcert
//!
//! A library for generating locally-trusted development certificates.
//!
//! fastcert creates a local certificate authority (CA) and uses it to sign
//! certificates for development. The CA can be installed in system trust stores
//! to make all certificates it signs trusted by browsers and tools.
//!
//! ## Quick Start
//!
//! ```no_run
//! use fastcert::CA;
//!
//! // Install CA to system trust stores
//! let ca = CA::load_or_create()?;
//! ca.install()?;
//!
//! // Generate a certificate
//! ca.issue_certificate()?
//!     .domains(vec!["example.com".to_string()])
//!     .build()?;
//! # Ok::<(), fastcert::Error>(())
//! ```
//!
//! ## Advanced Usage
//!
//! ```no_run
//! use fastcert::{CA, KeyType};
//! use std::path::PathBuf;
//!
//! // Custom CA location
//! let mut ca = CA::new(PathBuf::from("/custom/path"));
//! ca.init_ca()?;
//!
//! // Certificate with all options
//! ca.issue_certificate()?
//!     .domains(vec![
//!         "example.com".to_string(),
//!         "*.example.com".to_string(),
//!         "localhost".to_string(),
//!         "127.0.0.1".to_string(),
//!     ])
//!     .key_type(KeyType::ECDSA)
//!     .client_cert(true)
//!     .cert_file("my-cert.pem")
//!     .key_file("my-key.pem")
//!     .build()?;
//! # Ok::<(), fastcert::Error>(())
//! ```

pub mod ca;
pub mod cert;
pub mod error;
pub mod fileutil;
pub mod truststore;

// Re-export main types at crate root
pub use ca::CA;
pub use cert::{CertificateBuilder, KeyType};
pub use error::{Error, Result};

// Convenience functions for simple use cases

/// Generate a certificate with default settings
///
/// This is a convenience function that creates/loads the CA and generates
/// a certificate with the specified domains. For more control, use the
/// builder API via `CA::load_or_create()?.issue_certificate()`.
///
/// # Example
///
/// ```no_run
/// fastcert::generate_cert(&[
///     "example.com".to_string(),
///     "localhost".to_string(),
/// ])?;
/// # Ok::<(), fastcert::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if CA operations or certificate generation fails.
pub fn generate_cert(domains: &[String]) -> Result<()> {
    CA::load_or_create()?
        .issue_certificate()?
        .domains(domains.to_vec())
        .build()
}

/// Install the CA to system trust stores
///
/// Convenience function that loads/creates the CA and installs it.
/// For more control, use `CA::load_or_create()?.install()`.
///
/// # Example
///
/// ```no_run
/// fastcert::install()?;
/// # Ok::<(), fastcert::Error>(())
/// ```
pub fn install() -> Result<()> {
    let ca = CA::load_or_create()?;
    ca.install()
}

/// Uninstall the CA from system trust stores
///
/// Convenience function that uninstalls the CA without deleting it.
/// For more control, use `CA::load_or_create()?.uninstall()`.
///
/// # Example
///
/// ```no_run
/// fastcert::uninstall()?;
/// # Ok::<(), fastcert::Error>(())
/// ```
pub fn uninstall() -> Result<()> {
    let caroot = ca::get_caroot()?;
    let ca = CA::new(std::path::PathBuf::from(caroot));
    ca.uninstall()
}

/// Check if verbose mode is enabled
pub fn is_verbose() -> bool {
    std::env::var("FASTCERT_VERBOSE").is_ok()
}

/// Print verbose message
pub fn verbose_print(msg: &str) {
    if is_verbose() {
        eprintln!("[VERBOSE] {}", msg);
    }
}

/// Check if debug mode is enabled
pub fn is_debug() -> bool {
    std::env::var("FASTCERT_DEBUG").is_ok()
}

/// Print debug message
pub fn debug_print(msg: &str) {
    if is_debug() {
        eprintln!("[DEBUG] {}", msg);
    }
}

/// Log debug information about a value
pub fn debug_log<T: std::fmt::Debug>(label: &str, value: &T) {
    if is_debug() {
        eprintln!("[DEBUG] {}: {:?}", label, value);
    }
}

/// Check if quiet mode is enabled
pub fn is_quiet() -> bool {
    std::env::var("FASTCERT_QUIET").is_ok()
}

/// Print message only if not in quiet mode
pub fn info_print(msg: &str) {
    if !is_quiet() {
        println!("{}", msg);
    }
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

/// Get the configured output format
pub fn get_output_format() -> OutputFormat {
    std::env::var("FASTCERT_FORMAT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(OutputFormat::Text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Use a mutex to prevent concurrent test execution that could interfere with env vars
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_is_verbose_when_env_var_set() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_VERBOSE", "1");
        }
        assert!(is_verbose());
        unsafe {
            std::env::remove_var("FASTCERT_VERBOSE");
        }
    }

    #[test]
    fn test_is_verbose_when_env_var_not_set() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_VERBOSE");
        }
        assert!(!is_verbose());
    }

    #[test]
    fn test_verbose_print_when_enabled() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_VERBOSE", "1");
        }
        // Just ensure it doesn't panic
        verbose_print("test message");
        unsafe {
            std::env::remove_var("FASTCERT_VERBOSE");
        }
    }

    #[test]
    fn test_verbose_print_when_disabled() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_VERBOSE");
        }
        // Just ensure it doesn't panic
        verbose_print("test message");
    }

    #[test]
    fn test_is_debug_when_env_var_set() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_DEBUG", "1");
        }
        assert!(is_debug());
        unsafe {
            std::env::remove_var("FASTCERT_DEBUG");
        }
    }

    #[test]
    fn test_is_debug_when_env_var_not_set() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_DEBUG");
        }
        assert!(!is_debug());
    }

    #[test]
    fn test_debug_print_when_enabled() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_DEBUG", "1");
        }
        debug_print("test debug message");
        unsafe {
            std::env::remove_var("FASTCERT_DEBUG");
        }
    }

    #[test]
    fn test_debug_print_when_disabled() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_DEBUG");
        }
        debug_print("test debug message");
    }

    #[test]
    fn test_debug_log_when_enabled() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_DEBUG", "1");
        }
        let value = vec![1, 2, 3];
        debug_log("test vector", &value);
        unsafe {
            std::env::remove_var("FASTCERT_DEBUG");
        }
    }

    #[test]
    fn test_debug_log_when_disabled() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_DEBUG");
        }
        let value = vec![1, 2, 3];
        debug_log("test vector", &value);
    }

    #[test]
    fn test_is_quiet_when_env_var_set() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_QUIET", "1");
        }
        assert!(is_quiet());
        unsafe {
            std::env::remove_var("FASTCERT_QUIET");
        }
    }

    #[test]
    fn test_is_quiet_when_env_var_not_set() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_QUIET");
        }
        assert!(!is_quiet());
    }

    #[test]
    fn test_info_print_when_not_quiet() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_QUIET");
        }
        info_print("test info message");
    }

    #[test]
    fn test_info_print_when_quiet() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_QUIET", "1");
        }
        info_print("test info message");
        unsafe {
            std::env::remove_var("FASTCERT_QUIET");
        }
    }

    #[test]
    fn test_output_format_from_str_text() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("TEXT".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
    }

    #[test]
    fn test_output_format_from_str_json() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_yaml() {
        assert_eq!("yaml".parse::<OutputFormat>().unwrap(), OutputFormat::Yaml);
        assert_eq!("YAML".parse::<OutputFormat>().unwrap(), OutputFormat::Yaml);
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        let result = "invalid".parse::<OutputFormat>();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid output format: invalid".to_string()
        );
    }

    #[test]
    fn test_get_output_format_default() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FASTCERT_FORMAT");
        }
        assert_eq!(get_output_format(), OutputFormat::Text);
    }

    #[test]
    fn test_get_output_format_text() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_FORMAT", "text");
        }
        assert_eq!(get_output_format(), OutputFormat::Text);
        unsafe {
            std::env::remove_var("FASTCERT_FORMAT");
        }
    }

    #[test]
    fn test_get_output_format_json() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_FORMAT", "json");
        }
        assert_eq!(get_output_format(), OutputFormat::Json);
        unsafe {
            std::env::remove_var("FASTCERT_FORMAT");
        }
    }

    #[test]
    fn test_get_output_format_yaml() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_FORMAT", "yaml");
        }
        assert_eq!(get_output_format(), OutputFormat::Yaml);
        unsafe {
            std::env::remove_var("FASTCERT_FORMAT");
        }
    }

    #[test]
    fn test_get_output_format_invalid_defaults_to_text() {
        let _guard = TEST_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("FASTCERT_FORMAT", "invalid");
        }
        assert_eq!(get_output_format(), OutputFormat::Text);
        unsafe {
            std::env::remove_var("FASTCERT_FORMAT");
        }
    }

    #[test]
    fn test_output_format_debug() {
        let format = OutputFormat::Json;
        assert_eq!(format!("{:?}", format), "Json");
    }

    #[test]
    fn test_output_format_copy() {
        let format1 = OutputFormat::Yaml;
        let format2 = format1; // Copy trait automatically copies
        assert_eq!(format1, format2);
        // Verify format1 is still usable after "move" (because of Copy)
        assert_eq!(format1, OutputFormat::Yaml);
    }
}
