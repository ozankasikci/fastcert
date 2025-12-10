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
