//! rscert - A tool for creating locally-trusted development certificates
//!
//! This is a Rust implementation of mkcert.

pub mod error;
pub mod ca;
pub mod cert;
pub mod truststore;
pub mod fileutil;

pub use error::{Error, Result};
