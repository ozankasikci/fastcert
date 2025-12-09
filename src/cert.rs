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

#[derive(Debug, Clone, PartialEq)]
pub enum HostType {
    DnsName(String),
    IpAddress(IpAddr),
    Email(String),
    Uri(String),
}

impl HostType {
    pub fn parse(host: &str) -> Result<Self> {
        // Try IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(HostType::IpAddress(ip));
        }

        // Try email (simple check)
        if host.contains('@') && host.contains('.') {
            return Ok(HostType::Email(host.to_string()));
        }

        // Try URI (has scheme)
        if host.contains("://") {
            return Ok(HostType::Uri(host.to_string()));
        }

        // Default to DNS name
        Ok(HostType::DnsName(host.to_string()))
    }
}
