//! rscert - A tool for creating locally-trusted development certificates
//!
//! This is a Rust implementation of mkcert.

pub mod error;
pub mod ca;
pub mod cert;
pub mod truststore;
pub mod fileutil;

pub use error::{Error, Result};

/// Check if verbose mode is enabled
pub fn is_verbose() -> bool {
    std::env::var("RSCERT_VERBOSE").is_ok()
}

/// Print verbose message
pub fn verbose_print(msg: &str) {
    if is_verbose() {
        eprintln!("[VERBOSE] {}", msg);
    }
}

/// Check if debug mode is enabled
pub fn is_debug() -> bool {
    std::env::var("RSCERT_DEBUG").is_ok()
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
    std::env::var("RSCERT_QUIET").is_ok()
}

/// Print message only if not in quiet mode
pub fn info_print(msg: &str) {
    if !is_quiet() {
        println!("{}", msg);
    }
}
