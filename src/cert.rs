//! Certificate generation

use crate::{Error, Result};
use rcgen::{KeyPair, SanType, CertificateParams, KeyUsagePurpose, ExtendedKeyUsagePurpose, PKCS_RSA_SHA256, PKCS_ECDSA_P256_SHA256};
use regex::Regex;
use std::net::IpAddr;
use std::path::PathBuf;
use time::{OffsetDateTime, Duration};

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

pub fn validate_hostname(hostname: &str) -> Result<()> {
    let hostname_regex = Regex::new(r"(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$")
        .unwrap();

    if !hostname_regex.is_match(hostname) {
        return Err(Error::InvalidHostname(hostname.to_string()));
    }

    Ok(())
}

fn generate_keypair(use_ecdsa: bool) -> Result<KeyPair> {
    let alg = if use_ecdsa {
        &PKCS_ECDSA_P256_SHA256
    } else {
        &PKCS_RSA_SHA256
    };

    KeyPair::generate(alg)
        .map_err(|e| Error::Certificate(format!("Key generation failed: {}", e)))
}

/// Build Subject Alternative Names from a list of host strings
pub fn build_san_list(hosts: &[String]) -> Result<Vec<SanType>> {
    let mut san_list = Vec::new();

    for host in hosts {
        let host_type = HostType::parse(host)?;
        match host_type {
            HostType::DnsName(name) => {
                validate_hostname(&name)?;
                check_wildcard_warning(&name);
                san_list.push(SanType::DnsName(name));
            }
            HostType::IpAddress(ip) => {
                san_list.push(SanType::IpAddress(ip));
            }
            HostType::Email(email) => {
                san_list.push(SanType::Rfc822Name(email));
            }
            HostType::Uri(uri) => {
                san_list.push(SanType::URI(uri));
            }
        }
    }

    Ok(san_list)
}

/// Check for wildcard certificates and log warnings
fn check_wildcard_warning(name: &str) {
    // Check for second-level wildcards (e.g., *.com, *.net)
    let second_level_wildcard_regex = Regex::new(r"(?i)^\*\.[0-9a-z_-]+$").unwrap();
    if second_level_wildcard_regex.is_match(name) {
        eprintln!("Warning: many browsers don't support second-level wildcards like \"{}\"", name);
    }

    // General wildcard reminder
    if name.starts_with("*.") {
        eprintln!("Reminder: X.509 wildcards only go one level deep, so this won't match a.b.{}", &name[2..]);
    }
}

/// Create certificate parameters with proper validity period
/// Certificates last for 2 years and 3 months, which is always less than 825 days,
/// the limit that macOS/iOS apply to all certificates, including custom roots.
/// See https://support.apple.com/en-us/HT210176
pub fn create_cert_params(hosts: &[String]) -> Result<CertificateParams> {
    let mut params = CertificateParams::default();

    // Set validity period: 2 years and 3 months (always less than 825 days)
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    // 2 years = 730 days, 3 months ≈ 90 days = 820 days total (< 825 days)
    params.not_after = now + Duration::days(730 + 90);

    // Build and set SANs
    let san_list = build_san_list(hosts)?;
    params.subject_alt_names = san_list;

    // Set key usage for leaf certificates
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    Ok(params)
}

/// Add server authentication extended key usage
pub fn add_server_auth(params: &mut CertificateParams) {
    if !params.extended_key_usages.contains(&ExtendedKeyUsagePurpose::ServerAuth) {
        params.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
    }
}

/// Add client authentication extended key usage
pub fn add_client_auth(params: &mut CertificateParams) {
    if !params.extended_key_usages.contains(&ExtendedKeyUsagePurpose::ClientAuth) {
        params.extended_key_usages.push(ExtendedKeyUsagePurpose::ClientAuth);
    }
}

/// Add email protection extended key usage
pub fn add_email_protection(params: &mut CertificateParams) {
    if !params.extended_key_usages.contains(&ExtendedKeyUsagePurpose::EmailProtection) {
        params.extended_key_usages.push(ExtendedKeyUsagePurpose::EmailProtection);
    }
}

/// Serialize a certificate to PEM format
pub fn cert_to_pem(cert_der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", cert_der))
}

/// Serialize a private key to PEM format (PKCS#8)
pub fn key_to_pem(key: &KeyPair) -> Result<String> {
    let key_der = key.serialize_der();
    Ok(pem::encode(&pem::Pem::new("PRIVATE KEY", key_der)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_name() {
        let ht = HostType::parse("example.com").unwrap();
        assert_eq!(ht, HostType::DnsName("example.com".to_string()));
    }

    #[test]
    fn test_parse_ip() {
        let ht = HostType::parse("127.0.0.1").unwrap();
        match ht {
            HostType::IpAddress(_) => {},
            _ => panic!("Expected IP address"),
        }
    }

    #[test]
    fn test_parse_email() {
        let ht = HostType::parse("test@example.com").unwrap();
        assert_eq!(ht, HostType::Email("test@example.com".to_string()));
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("*.example.com").is_ok());
        assert!(validate_hostname("localhost").is_ok());
    }

    #[test]
    fn test_invalid_hostname() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("..").is_err());
    }
}
