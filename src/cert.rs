//! Certificate generation

use crate::{Error, Result};
use std::net::IpAddr;
use std::path::PathBuf;

pub struct CertificateConfig {
    pub hosts: Vec<String>,
    pub use_ecdsa: bool,
    pub client_cert: bool,
    pub pkcs12: bool,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub p12_file: Option<PathBuf>,
}

impl CertificateConfig {
    pub fn new(hosts: Vec<String>) -> Self {
        Self {
            hosts,
            use_ecdsa: false,
            client_cert: false,
            pkcs12: false,
            cert_file: None,
            key_file: None,
            p12_file: None,
        }
    }
}
