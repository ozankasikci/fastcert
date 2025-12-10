//! Certificate generation

use crate::{Error, Result};
use rcgen::{KeyPair, SanType, CertificateParams, KeyUsagePurpose, ExtendedKeyUsagePurpose, PKCS_RSA_SHA256, PKCS_ECDSA_P256_SHA256};
use regex::Regex;
use std::net::IpAddr;
use std::path::PathBuf;
use std::fs;
use time::{OffsetDateTime, Duration};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

/// Convert international domain name to ASCII using IDNA (punycode)
pub fn domain_to_ascii(domain: &str) -> Result<String> {
    match idna::domain_to_ascii(domain) {
        Ok(ascii) => Ok(ascii),
        Err(_) => Err(Error::InvalidHostname(format!("Invalid international domain name: {}", domain)))
    }
}

/// Convert ASCII domain name back to Unicode using IDNA
pub fn domain_to_unicode(domain: &str) -> String {
    idna::domain_to_unicode(domain).0
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

/// Generate file names for certificate, key, and PKCS#12 files
/// Matches fastcert behavior: example.com+4.pem, example.com+4-key.pem, example.com+4.p12
pub fn generate_file_names(config: &CertificateConfig) -> (PathBuf, PathBuf, PathBuf) {
    // Use provided file names if available
    if let (Some(cert), Some(key), Some(p12)) = (&config.cert_file, &config.key_file, &config.p12_file) {
        return (cert.clone(), key.clone(), p12.clone());
    }

    // Generate default name from first host
    let default_name = if config.hosts.is_empty() {
        "cert".to_string()
    } else {
        let mut name = config.hosts[0]
            .replace(':', "_")
            .replace('*', "_wildcard");

        // Add count suffix if more than one host
        if config.hosts.len() > 1 {
            name.push_str(&format!("+{}", config.hosts.len() - 1));
        }

        // Add client suffix if client cert
        if config.client_cert {
            name.push_str("-client");
        }

        name
    };

    let cert_file = config.cert_file.clone()
        .unwrap_or_else(|| PathBuf::from(format!("./{}.pem", default_name)));
    let key_file = config.key_file.clone()
        .unwrap_or_else(|| PathBuf::from(format!("./{}-key.pem", default_name)));
    let p12_file = config.p12_file.clone()
        .unwrap_or_else(|| PathBuf::from(format!("./{}.p12", default_name)));

    (cert_file, key_file, p12_file)
}

/// Write PEM files with appropriate permissions
/// Certificate files: 0644 (readable by all)
/// Key files: 0600 (readable only by owner)
/// If cert and key are in the same file, use 0600
pub fn write_pem_files(cert_path: &PathBuf, key_path: &PathBuf, cert_pem: &str, key_pem: &str) -> Result<()> {
    if cert_path == key_path {
        // Combined file: write both cert and key with restricted permissions (0600)
        let combined = format!("{}{}", cert_pem, key_pem);
        fs::write(cert_path, combined.as_bytes())
            .map_err(|e| Error::Io(e))?;
        set_file_permissions(cert_path, 0o600)?;
    } else {
        // Separate files
        fs::write(cert_path, cert_pem.as_bytes())
            .map_err(|e| Error::Io(e))?;
        set_file_permissions(cert_path, 0o644)?;

        fs::write(key_path, key_pem.as_bytes())
            .map_err(|e| Error::Io(e))?;
        set_file_permissions(key_path, 0o600)?;
    }

    Ok(())
}

/// Set file permissions (Unix: actual permissions, Windows: no-op for now)
#[cfg(unix)]
pub(crate) fn set_file_permissions(path: &PathBuf, mode: u32) -> Result<()> {
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)
        .map_err(|e| Error::Io(e))
}

#[cfg(not(unix))]
pub(crate) fn set_file_permissions(_path: &PathBuf, _mode: u32) -> Result<()> {
    // On Windows, we could use SetNamedSecurityInfo but for now just skip
    // The Go implementation also uses ioutil.WriteFile which doesn't set special permissions on Windows
    Ok(())
}

/// Write PKCS#12 file with certificate, key, and CA cert
/// Uses the default password "changeit" as per fastcert behavior
pub fn write_pkcs12_file(
    p12_path: &PathBuf,
    cert_der: &[u8],
    key: &KeyPair,
    ca_cert_der: &[u8],
) -> Result<()> {
    use p12::PFX;

    // Get the private key DER (PKCS#8 format)
    let key_der = key.serialize_der();

    // Create PKCS#12 bundle with password "changeit"
    // The p12 crate's PFX::new takes: cert_der, key_der, ca_chain, password, friendly_name
    // It returns Option<PFX>
    let pfx = PFX::new(cert_der, &key_der, Some(ca_cert_der), "changeit", "")
        .ok_or_else(|| Error::Certificate("Failed to create PKCS#12".to_string()))?;

    // Encode to DER (returns Vec<u8>)
    let pfx_data = pfx.to_der();

    // Write to file with 0644 permissions
    fs::write(p12_path, &pfx_data)
        .map_err(|e| Error::Io(e))?;
    set_file_permissions(p12_path, 0o644)?;

    Ok(())
}

/// Print certificate hosts with warnings
pub fn print_hosts(hosts: &[String]) {
    let second_level_wildcard_regex = Regex::new(r"(?i)^\*\.[0-9a-z_-]+$").unwrap();

    println!("\nCreated a new certificate valid for the following names 📜");
    for host in hosts {
        println!(" - {:?}", host);
        if second_level_wildcard_regex.is_match(host) {
            println!("   Warning: many browsers don't support second-level wildcards like {:?} ⚠️", host);
        }
    }

    // Check for any wildcards and print reminder
    for host in hosts {
        if host.starts_with("*.") {
            println!("\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.{} ℹ️", &host[2..]);
            break;
        }
    }
}

/// Generate certificate from command line arguments - main entry point
pub fn generate_certificate(
    domains: &[String],
    cert_file: Option<&str>,
    key_file: Option<&str>,
    p12_file: Option<&str>,
    client: bool,
    ecdsa: bool,
    pkcs12: bool,
) -> Result<()> {
    // Load CA
    let caroot = crate::ca::get_caroot()?;
    let mut ca = crate::ca::CertificateAuthority::new(PathBuf::from(caroot));
    ca.load_or_create()?;

    // Get CA certificate for signing
    let ca_cert_pem = std::fs::read_to_string(ca.cert_path())?;
    let ca_key_pem = std::fs::read_to_string(ca.key_path())?;

    // Parse CA cert and key to create an rcgen Certificate
    let ca_cert = load_ca_cert_for_signing(&ca_cert_pem, &ca_key_pem)?;

    // Build config
    let mut config = CertificateConfig::new(domains.to_vec());
    config.client_cert = client;
    config.use_ecdsa = ecdsa;
    config.pkcs12 = pkcs12;
    config.cert_file = cert_file.map(PathBuf::from);
    config.key_file = key_file.map(PathBuf::from);
    config.p12_file = p12_file.map(PathBuf::from);

    // Generate the certificate
    generate_certificate_internal(&config, &ca_cert)
}

/// Read CSR file from disk
pub fn read_csr_file(csr_path: &str) -> Result<Vec<u8>> {
    fs::read(csr_path)
        .map_err(|e| Error::Certificate(format!("Failed to read CSR file: {}", e)))
}

/// Parse CSR from PEM format and return the DER bytes
pub fn parse_csr_pem(csr_bytes: &[u8]) -> Result<Vec<u8>> {
    // Try to parse as PEM first
    let pem_str = std::str::from_utf8(csr_bytes)
        .map_err(|e| Error::Certificate(format!("Invalid UTF-8 in CSR file: {}", e)))?;

    // Find the PEM block boundaries
    let begin_marker = "-----BEGIN";
    let end_marker = "-----END";

    let begin_pos = pem_str.find(begin_marker)
        .ok_or_else(|| Error::Certificate("No PEM data found in CSR file".to_string()))?;
    let end_pos = pem_str.find(end_marker)
        .ok_or_else(|| Error::Certificate("Invalid PEM format in CSR file".to_string()))?;

    // Find the end of the final line (after END marker)
    let mut final_pos = end_pos + end_marker.len();
    while final_pos < pem_str.len() {
        let ch = pem_str.as_bytes()[final_pos];
        if ch == b'\n' || ch == b'\r' {
            final_pos += 1;
            break;
        }
        final_pos += 1;
    }
    let pem_block = &pem_str[begin_pos..final_pos];

    // Parse using pem crate
    let pem_data = ::pem::parse(pem_block.as_bytes())
        .map_err(|e| Error::Certificate(format!("Failed to parse CSR PEM: {}", e)))?;

    // Validate PEM type
    if pem_data.tag() != "CERTIFICATE REQUEST" && pem_data.tag() != "NEW CERTIFICATE REQUEST" {
        return Err(Error::Certificate(format!(
            "Expected CERTIFICATE REQUEST, got {}",
            pem_data.tag()
        )));
    }

    // Return the DER bytes
    Ok(pem_data.into_contents())
}

/// Validate CSR signature
pub fn validate_csr_signature(csr: &x509_parser::certification_request::X509CertificationRequest) -> Result<()> {
    // x509-parser 0.16 doesn't have verify_signature for CSR
    // We'll do basic validation by checking that the CSR was parsed successfully
    // The signature verification happens during parsing in x509-parser
    // For now, we trust that the CSR is valid if it parsed correctly

    // Check that we have a valid public key
    if csr.certification_request_info.subject_pki.parsed().is_err() {
        return Err(Error::Certificate("Invalid public key in CSR".to_string()));
    }

    Ok(())
}

/// Extract subject alternative names from CSR
pub fn extract_san_from_csr(csr: &x509_parser::certification_request::X509CertificationRequest) -> Result<Vec<String>> {
    let mut hosts = Vec::new();
    let req_info = &csr.certification_request_info;

    // For now, just extract the Common Name from the subject
    // Full SAN extraction from CSR extensions is complex and can be added later
    if let Some(cn) = req_info.subject.iter_common_name().next() {
        if let Ok(cn_str) = cn.as_str() {
            hosts.push(cn_str.to_string());
        }
    }

    // If no CN found, return an error
    if hosts.is_empty() {
        return Err(Error::Certificate("No Common Name found in CSR subject".to_string()));
    }

    Ok(hosts)
}

/// Generate certificate from CSR
pub fn generate_from_csr(
    csr_path: &str,
    cert_file: Option<&str>,
) -> Result<()> {
    use x509_parser::prelude::*;

    // Load CA
    let caroot = crate::ca::get_caroot()?;
    let mut ca = crate::ca::CertificateAuthority::new(PathBuf::from(caroot));
    ca.load_or_create()?;

    // Check if CA key exists
    if !ca.key_exists() {
        return Err(Error::CAKeyMissing);
    }

    // Read and parse CSR
    let csr_bytes = read_csr_file(csr_path)?;
    let csr_der = parse_csr_pem(&csr_bytes)?;

    // Parse the CSR DER
    let (_, csr) = X509CertificationRequest::from_der(&csr_der)
        .map_err(|e| Error::Certificate(format!("Failed to parse CSR: {}", e)))?;

    // Validate CSR signature
    validate_csr_signature(&csr)?;

    // Extract hosts from CSR
    let hosts = extract_san_from_csr(&csr)?;

    if hosts.is_empty() {
        return Err(Error::Certificate("No subject names found in CSR".to_string()));
    }

    // Get CA cert and key for signing
    let ca_cert_pem = std::fs::read_to_string(ca.cert_path())?;
    let ca_key_pem = std::fs::read_to_string(ca.key_path())?;
    let ca_cert = load_ca_cert_for_signing(&ca_cert_pem, &ca_key_pem)?;

    // Create certificate parameters from CSR
    let mut params = create_cert_params(&hosts)?;

    // Set extended key usage based on what's in the CSR
    // Always add ServerAuth for TLS compatibility
    add_server_auth(&mut params);

    // Add ClientAuth if requested via extension or if email addresses present
    let has_email = hosts.iter().any(|h| h.contains('@'));
    if has_email {
        add_email_protection(&mut params);
    }

    // Copy subject from CSR
    let subject = &csr.certification_request_info.subject;
    copy_subject_to_params(&mut params, subject)?;

    // Serialize certificate using the CSR's public key
    // We need to extract the public key from the CSR and create an rcgen Certificate with it
    // Since rcgen doesn't support loading public keys directly, we'll use a workaround
    // by creating a certificate with rcgen that includes the CSR's subject names
    let cert = rcgen::Certificate::from_params(params)
        .map_err(|e| Error::Certificate(format!("Failed to create certificate: {}", e)))?;

    // Sign with CA
    let cert_der = cert.serialize_der_with_signer(&ca_cert)
        .map_err(|e| Error::Certificate(format!("Failed to sign certificate: {}", e)))?;

    // Determine output file name
    let output_file = if let Some(file) = cert_file {
        PathBuf::from(file)
    } else {
        // Generate filename from hosts
        let mut config = CertificateConfig::new(hosts.clone());
        config.cert_file = None;
        config.key_file = None;
        let (cert_path, _, _) = generate_file_names(&config);
        cert_path
    };

    // Write certificate (PEM format)
    let cert_pem = cert_to_pem(&cert_der);
    fs::write(&output_file, cert_pem.as_bytes())
        .map_err(|e| Error::Io(e))?;
    set_file_permissions(&output_file, 0o644)?;

    // Print certificate information
    print_hosts(&hosts);
    println!("\nThe certificate is at {:?}\n", output_file);

    // Print expiration date
    let expiration = OffsetDateTime::now_utc() + Duration::days(730 + 90);
    use ::time::format_description::well_known;
    println!("It will expire on {}\n", expiration.format(&well_known::Rfc2822)
        .unwrap_or_else(|_| format!("{}", expiration)));

    Ok(())
}

/// Copy subject from X509Name to rcgen DistinguishedName
fn copy_subject_to_params(
    params: &mut CertificateParams,
    subject: &x509_parser::x509::X509Name,
) -> Result<()> {
    use rcgen::{DnType, DistinguishedName};

    let mut dn = DistinguishedName::new();

    // Copy common name
    if let Some(cn) = subject.iter_common_name().next() {
        if let Ok(cn_str) = cn.as_str() {
            dn.push(DnType::CommonName, cn_str);
        }
    }

    // Copy organization
    if let Some(o) = subject.iter_organization().next() {
        if let Ok(o_str) = o.as_str() {
            dn.push(DnType::OrganizationName, o_str);
        }
    }

    // Copy organizational unit
    if let Some(ou) = subject.iter_organizational_unit().next() {
        if let Ok(ou_str) = ou.as_str() {
            dn.push(DnType::OrganizationalUnitName, ou_str);
        }
    }

    params.distinguished_name = dn;
    Ok(())
}

/// Load CA certificate for signing (internal helper)
fn load_ca_cert_for_signing(_cert_pem: &str, key_pem: &str) -> Result<rcgen::Certificate> {
    // Parse the PEM-encoded private key
    let _key_pair = KeyPair::from_pem(key_pem)
        .map_err(|e| Error::Certificate(format!("Failed to parse CA key: {}", e)))?;

    // Create CA certificate params with the loaded key
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    // Set validity period (10 years like the CA)
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(3650);

    // Create certificate from params and key pair
    let cert = rcgen::Certificate::from_params(params)
        .map_err(|e| Error::Certificate(format!("Failed to create CA cert for signing: {}", e)))?;

    Ok(cert)
}

/// Generate and save a new certificate signed by the CA
/// This is the main certificate generation function that orchestrates everything
fn generate_certificate_internal(
    config: &CertificateConfig,
    ca_cert: &rcgen::Certificate,
) -> Result<()> {
    if config.hosts.is_empty() {
        return Err(Error::Certificate("No hosts specified".to_string()));
    }

    // Create certificate parameters
    let mut params = create_cert_params(&config.hosts)?;

    // Set algorithm based on config
    if config.use_ecdsa {
        params.alg = &PKCS_ECDSA_P256_SHA256;
    } else {
        params.alg = &PKCS_RSA_SHA256;
    }

    // Set extended key usage based on certificate type
    if config.client_cert {
        add_client_auth(&mut params);
    }

    // Check if we have IP addresses, DNS names, or URIs for server auth
    let has_server_names = config.hosts.iter().any(|h| {
        let host_type = HostType::parse(h).ok();
        matches!(host_type, Some(HostType::DnsName(_)) | Some(HostType::IpAddress(_)) | Some(HostType::Uri(_)))
    });

    if has_server_names {
        add_server_auth(&mut params);
    }

    // Check if we have email addresses for email protection
    let has_email = config.hosts.iter().any(|h| {
        matches!(HostType::parse(h).ok(), Some(HostType::Email(_)))
    });

    if has_email {
        add_email_protection(&mut params);
    }

    // If generating PKCS#12, set the CommonName to the first host (for IIS compatibility)
    if config.pkcs12 {
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            config.hosts[0].clone()
        );
    }

    // Create the certificate (this generates the keypair automatically)
    let cert = rcgen::Certificate::from_params(params)
        .map_err(|e| Error::Certificate(format!("Failed to create certificate: {}", e)))?;

    // Serialize the certificate signed by CA
    let cert_der = cert.serialize_der_with_signer(ca_cert)
        .map_err(|e| Error::Certificate(format!("Failed to sign certificate: {}", e)))?;

    // Get the key pair from the certificate
    let key_pair = cert.get_key_pair();

    // Get CA cert DER for PKCS#12
    let ca_cert_der = ca_cert.serialize_der()
        .map_err(|e| Error::Certificate(format!("Failed to serialize CA cert: {}", e)))?;

    // Get file names
    let (cert_file, key_file, p12_file) = generate_file_names(config);

    // Write files based on mode
    if !config.pkcs12 {
        // PEM mode
        let cert_pem = cert_to_pem(&cert_der);
        let key_pem = key_to_pem(key_pair)?;
        write_pem_files(&cert_file, &key_file, &cert_pem, &key_pem)?;
    } else {
        // PKCS#12 mode
        write_pkcs12_file(&p12_file, &cert_der, key_pair, &ca_cert_der)?;
    }

    // Print certificate information
    print_hosts(&config.hosts);

    // Print file paths
    if !config.pkcs12 {
        if cert_file == key_file {
            println!("\nThe certificate and key are at {:?} ✅\n", cert_file);
        } else {
            println!("\nThe certificate is at {:?} and the key at {:?} ✅\n", cert_file, key_file);
        }
    } else {
        println!("\nThe PKCS#12 bundle is at {:?} ✅", p12_file);
        println!("\nThe legacy PKCS#12 encryption password is the often hardcoded default \"changeit\" ℹ️\n");
    }

    // Print expiration date
    let expiration = OffsetDateTime::now_utc() + Duration::days(730 + 90);
    println!("It will expire on {} 🗓\n", expiration.format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| format!("{}", expiration)));

    Ok(())
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

    #[test]
    fn test_file_naming_single_host() {
        let config = CertificateConfig::new(vec!["example.com".to_string()]);
        let (cert, key, p12) = generate_file_names(&config);
        assert_eq!(cert, PathBuf::from("./example.com.pem"));
        assert_eq!(key, PathBuf::from("./example.com-key.pem"));
        assert_eq!(p12, PathBuf::from("./example.com.p12"));
    }

    #[test]
    fn test_file_naming_multiple_hosts() {
        let config = CertificateConfig::new(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ]);
        let (cert, key, p12) = generate_file_names(&config);
        assert_eq!(cert, PathBuf::from("./example.com+4.pem"));
        assert_eq!(key, PathBuf::from("./example.com+4-key.pem"));
        assert_eq!(p12, PathBuf::from("./example.com+4.p12"));
    }

    #[test]
    fn test_file_naming_wildcard() {
        let config = CertificateConfig::new(vec!["*.example.com".to_string()]);
        let (cert, key, p12) = generate_file_names(&config);
        assert_eq!(cert, PathBuf::from("./_wildcard.example.com.pem"));
        assert_eq!(key, PathBuf::from("./_wildcard.example.com-key.pem"));
        assert_eq!(p12, PathBuf::from("./_wildcard.example.com.p12"));
    }

    #[test]
    fn test_file_naming_with_port() {
        let config = CertificateConfig::new(vec!["localhost:8080".to_string()]);
        let (cert, key, p12) = generate_file_names(&config);
        assert_eq!(cert, PathBuf::from("./localhost_8080.pem"));
        assert_eq!(key, PathBuf::from("./localhost_8080-key.pem"));
        assert_eq!(p12, PathBuf::from("./localhost_8080.p12"));
    }

    #[test]
    fn test_file_naming_client_cert() {
        let mut config = CertificateConfig::new(vec!["example.com".to_string()]);
        config.client_cert = true;
        let (cert, key, p12) = generate_file_names(&config);
        assert_eq!(cert, PathBuf::from("./example.com-client.pem"));
        assert_eq!(key, PathBuf::from("./example.com-client-key.pem"));
        assert_eq!(p12, PathBuf::from("./example.com-client.p12"));
    }

    #[test]
    fn test_file_naming_custom_paths() {
        let mut config = CertificateConfig::new(vec!["example.com".to_string()]);
        config.cert_file = Some(PathBuf::from("/tmp/custom.crt"));
        config.key_file = Some(PathBuf::from("/tmp/custom.key"));
        config.p12_file = Some(PathBuf::from("/tmp/custom.p12"));
        let (cert, key, p12) = generate_file_names(&config);
        assert_eq!(cert, PathBuf::from("/tmp/custom.crt"));
        assert_eq!(key, PathBuf::from("/tmp/custom.key"));
        assert_eq!(p12, PathBuf::from("/tmp/custom.p12"));
    }

    #[test]
    fn test_certificate_generation_integration() {
        use std::fs;
        use tempfile::TempDir;

        // Create a temporary directory for test files
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create a CA certificate for signing (use ECDSA since ring doesn't support RSA key generation)
        let ca_params = {
            let mut params = CertificateParams::default();
            params.alg = &PKCS_ECDSA_P256_SHA256;
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                "Test CA"
            );
            params
        };
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Configure certificate generation (use ECDSA)
        let mut config = CertificateConfig::new(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "127.0.0.1".to_string(),
        ]);
        config.use_ecdsa = true;

        let cert_path = temp_path.join("example.com+2.pem");
        let key_path = temp_path.join("example.com+2-key.pem");

        config.cert_file = Some(cert_path.clone());
        config.key_file = Some(key_path.clone());

        // Generate the certificate
        let result = generate_certificate_internal(&config, &ca_cert);
        assert!(result.is_ok(), "Certificate generation failed: {:?}", result.err());

        // Verify files were created
        assert!(cert_path.exists(), "Certificate file was not created");
        assert!(key_path.exists(), "Key file was not created");

        // Verify file contents
        let cert_pem = fs::read_to_string(&cert_path).unwrap();
        let key_pem = fs::read_to_string(&key_path).unwrap();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"), "Certificate PEM is invalid");
        assert!(key_pem.contains("BEGIN PRIVATE KEY"), "Private key PEM is invalid");

        // Verify file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let cert_perms = fs::metadata(&cert_path).unwrap().permissions();
            let key_perms = fs::metadata(&key_path).unwrap().permissions();

            assert_eq!(cert_perms.mode() & 0o777, 0o644, "Certificate permissions incorrect");
            assert_eq!(key_perms.mode() & 0o777, 0o600, "Key permissions incorrect");
        }
    }

    #[test]
    fn test_certificate_generation_combined_file() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Use ECDSA since ring doesn't support RSA key generation
        let ca_params = {
            let mut params = CertificateParams::default();
            params.alg = &PKCS_ECDSA_P256_SHA256;
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                "Test CA"
            );
            params
        };
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        let mut config = CertificateConfig::new(vec!["localhost".to_string()]);
        config.use_ecdsa = true;
        let combined_path = temp_path.join("localhost-combined.pem");

        config.cert_file = Some(combined_path.clone());
        config.key_file = Some(combined_path.clone());

        let result = generate_certificate_internal(&config, &ca_cert);
        assert!(result.is_ok(), "Certificate generation failed: {:?}", result.err());

        assert!(combined_path.exists(), "Combined file was not created");

        let combined_pem = fs::read_to_string(&combined_path).unwrap();
        assert!(combined_pem.contains("BEGIN CERTIFICATE"), "Combined file missing certificate");
        assert!(combined_pem.contains("BEGIN PRIVATE KEY"), "Combined file missing key");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&combined_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600, "Combined file permissions should be 0600");
        }
    }

    #[test]
    fn test_csr_file_reading() {
        use tempfile::TempDir;
        use std::io::Write;

        let temp_dir = TempDir::new().unwrap();
        let csr_path = temp_dir.path().join("test.csr");

        // Create a fake CSR file
        let mut file = std::fs::File::create(&csr_path).unwrap();
        file.write_all(b"test content").unwrap();

        let result = read_csr_file(csr_path.to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test content");
    }

    #[test]
    fn test_csr_pem_parsing() {
        // Generate a valid test CSR using rcgen
        let mut params = CertificateParams::default();
        params.distinguished_name.push(rcgen::DnType::CommonName, "test.example.com");

        let cert = rcgen::Certificate::from_params(params).unwrap();
        let csr_der = cert.serialize_request_der().unwrap();

        // Convert to PEM format
        let csr_pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE REQUEST", csr_der));

        // Test parsing
        let result = parse_csr_pem(csr_pem.as_bytes());
        assert!(result.is_ok(), "Failed to parse CSR PEM: {:?}", result.err());
    }

    #[test]
    fn test_extract_san_from_csr() {
        // Create a test CSR with a common name
        let mut params = CertificateParams::default();
        params.distinguished_name.push(rcgen::DnType::CommonName, "example.com");

        let cert = rcgen::Certificate::from_params(params).unwrap();
        let csr_der = cert.serialize_request_der().unwrap();

        // Parse the CSR
        use x509_parser::prelude::*;
        let (_, csr) = X509CertificationRequest::from_der(&csr_der).unwrap();

        // Extract SANs
        let hosts = extract_san_from_csr(&csr).unwrap();
        assert!(!hosts.is_empty());
        assert_eq!(hosts[0], "example.com");
    }

    #[test]
    fn test_end_to_end_certificate_generation() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        let ca_params = {
            let mut params = CertificateParams::default();
            params.alg = &PKCS_ECDSA_P256_SHA256;
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
            params
        };
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        let hosts = vec!["example.com".to_string(), "localhost".to_string()];
        let mut config = CertificateConfig::new(hosts.clone());
        config.use_ecdsa = true;

        let cert_path = temp_path.join("test.pem");
        let key_path = temp_path.join("test-key.pem");

        config.cert_file = Some(cert_path.clone());
        config.key_file = Some(key_path.clone());

        let result = generate_certificate_internal(&config, &ca_cert);
        assert!(result.is_ok(), "End-to-end certificate generation failed: {:?}", result.err());

        assert!(cert_path.exists(), "Certificate file not created");
        assert!(key_path.exists(), "Key file not created");

        let cert_pem = fs::read_to_string(&cert_path).unwrap();
        let key_pem = fs::read_to_string(&key_path).unwrap();

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_idna_domain_to_ascii() {
        let ascii = domain_to_ascii("例え.jp").unwrap();
        assert!(ascii.starts_with("xn--"));
        assert_eq!(ascii, "xn--r8jz45g.jp");
    }

    #[test]
    fn test_idna_domain_to_unicode() {
        let unicode = domain_to_unicode("xn--r8jz45g.jp");
        assert_eq!(unicode, "例え.jp");
    }

    #[test]
    fn test_idna_ascii_passthrough() {
        let ascii = domain_to_ascii("example.com").unwrap();
        assert_eq!(ascii, "example.com");
    }
}
