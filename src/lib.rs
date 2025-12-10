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
