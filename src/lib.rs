//! fastcert - A tool for creating locally-trusted development certificates

pub mod ca;
pub mod cert;
pub mod error;
pub mod fileutil;
pub mod truststore;

pub use error::{Error, Result};

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
    fn test_output_format_clone() {
        let format1 = OutputFormat::Yaml;
        let format2 = format1.clone();
        assert_eq!(format1, format2);
    }

    #[test]
    fn test_output_format_copy() {
        let format1 = OutputFormat::Json;
        let format2 = format1;
        assert_eq!(format1, format2);
    }
}
