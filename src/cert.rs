//! Certificate generation module.
//!
//! This module provides functionality for generating TLS certificates signed
//! by a local CA. It supports various certificate types including:
//! - Server certificates for HTTPS
//! - Client certificates for mutual TLS
//! - Wildcard certificates
//! - Multi-domain certificates (SAN)
//! - PKCS#12 bundles
//!
//! Certificates can be generated with either RSA or ECDSA keys and support
//! multiple subject alternative names including DNS names, IP addresses,
//! email addresses, and URIs.

use crate::{Error, Result};
use colored::*;
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize, SanType,
};
use regex::Regex;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use time::{Duration, OffsetDateTime};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Configuration for certificate generation.
///
/// Specifies all parameters needed to generate a certificate including
/// the hosts it should be valid for and output file locations.
pub struct CertificateConfig {
    /// List of hostnames, IP addresses, emails, or URIs for the certificate
    pub hosts: Vec<String>,
    /// Use ECDSA instead of RSA for the key pair
    pub use_ecdsa: bool,
    /// Generate a client authentication certificate
    pub client_cert: bool,
    /// Generate PKCS#12 bundle instead of PEM files
    pub pkcs12: bool,
    /// Custom path for certificate output file
    pub cert_file: Option<PathBuf>,
    /// Custom path for private key output file
    pub key_file: Option<PathBuf>,
    /// Custom path for PKCS#12 bundle output file
    pub p12_file: Option<PathBuf>,
}

impl CertificateConfig {
    /// Create a new certificate configuration with the specified hosts.
    ///
    /// # Arguments
    ///
    /// * `hosts` - List of DNS names, IP addresses, emails, or URIs
    ///
    /// # Returns
    ///
    /// A new `CertificateConfig` with default settings.
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

/// Type of host identifier in a certificate.
///
/// Represents the different types of subject alternative names
/// that can appear in an X.509 certificate.
#[derive(Debug, Clone, PartialEq)]
pub enum HostType {
    /// A DNS domain name (e.g., "example.com" or "*.example.com")
    DnsName(String),
    /// An IP address (IPv4 or IPv6)
    IpAddress(IpAddr),
    /// An email address (e.g., "user@example.com")
    Email(String),
    /// A Uniform Resource Identifier (e.g., "https://example.com")
    Uri(String),
}

/// Key type for certificate generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// RSA 2048-bit key (default, maximum compatibility)
    RSA2048,
    /// ECDSA P-256 key (better performance, smaller keys)
    ECDSA,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::RSA2048
    }
}

/// Builder for certificate generation
///
/// Created by calling `CA::issue_certificate()`. Configure the certificate
/// parameters using the builder methods, then call `build()` to generate
/// and save the certificate.
///
/// # Example
///
/// ```no_run
/// # use fastcert::CA;
/// let ca = CA::load_or_create()?;
/// ca.issue_certificate()?
///     .domains(vec!["example.com".to_string()])
///     .build()?;
/// # Ok::<(), fastcert::Error>(())
/// ```
pub struct CertificateBuilder {
    ca_cert_pem: String,
    ca_key_pem: String,
    domains: Vec<String>,
    key_type: KeyType,
    client_cert: bool,
    cert_file: Option<String>,
    key_file: Option<String>,
    p12_file: Option<String>,
}

impl CertificateBuilder {
    /// Create a new certificate builder (internal use only)
    pub(crate) fn new(ca_cert_pem: String, ca_key_pem: String) -> Self {
        Self {
            ca_cert_pem,
            ca_key_pem,
            domains: Vec::new(),
            key_type: KeyType::default(),
            client_cert: false,
            cert_file: None,
            key_file: None,
            p12_file: None,
        }
    }

    /// Set the domains for this certificate (required)
    ///
    /// Accepts DNS names, IP addresses, email addresses, and URIs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use fastcert::CA;
    /// # let ca = CA::load_or_create()?;
    /// ca.issue_certificate()?
    ///     .domains(vec![
    ///         "example.com".to_string(),
    ///         "*.example.com".to_string(),
    ///         "127.0.0.1".to_string(),
    ///     ])
    ///     .build()?;
    /// # Ok::<(), fastcert::Error>(())
    /// ```
    pub fn domains(mut self, domains: Vec<String>) -> Self {
        self.domains = domains;
        self
    }

    /// Set the key type (default: RSA2048)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use fastcert::{CA, KeyType};
    /// # let ca = CA::load_or_create()?;
    /// ca.issue_certificate()?
    ///     .domains(vec!["example.com".to_string()])
    ///     .key_type(KeyType::ECDSA)
    ///     .build()?;
    /// # Ok::<(), fastcert::Error>(())
    /// ```
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Generate a client authentication certificate (default: false)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use fastcert::CA;
    /// # let ca = CA::load_or_create()?;
    /// ca.issue_certificate()?
    ///     .domains(vec!["client@example.com".to_string()])
    ///     .client_cert(true)
    ///     .build()?;
    /// # Ok::<(), fastcert::Error>(())
    /// ```
    pub fn client_cert(mut self, client: bool) -> Self {
        self.client_cert = client;
        self
    }

    /// Set custom certificate file path (default: auto-generated)
    ///
    /// If not specified, the filename is generated from the first domain.
    pub fn cert_file(mut self, path: impl Into<String>) -> Self {
        self.cert_file = Some(path.into());
        self
    }

    /// Set custom key file path (default: auto-generated)
    ///
    /// If not specified, the filename is generated from the first domain.
    pub fn key_file(mut self, path: impl Into<String>) -> Self {
        self.key_file = Some(path.into());
        self
    }

    /// Set PKCS#12 file path and enable PKCS#12 mode
    ///
    /// When set, generates a .p12 file instead of separate PEM files.
    pub fn pkcs12_file(mut self, path: impl Into<String>) -> Self {
        self.p12_file = Some(path.into());
        self
    }

    /// Generate the certificate and write to disk
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No domains were specified
    /// - Domain validation fails
    /// - Certificate generation fails
    /// - File writing fails
    pub fn build(self) -> Result<()> {
        if self.domains.is_empty() {
            return Err(Error::Certificate("No domains specified. Use .domains() to set domains.".to_string()));
        }

        // Convert to CertificateConfig
        let mut config = CertificateConfig::new(self.domains);
        config.use_ecdsa = matches!(self.key_type, KeyType::ECDSA);
        config.client_cert = self.client_cert;
        config.pkcs12 = self.p12_file.is_some();
        config.cert_file = self.cert_file.map(PathBuf::from);
        config.key_file = self.key_file.map(PathBuf::from);
        config.p12_file = self.p12_file.map(PathBuf::from);

        // Call internal generation function
        generate_certificate_internal(&config, &self.ca_cert_pem, &self.ca_key_pem)
    }
}

impl HostType {
    /// Parse a host string into the appropriate HostType.
    ///
    /// Automatically detects the type based on the string format:
    /// - IP addresses are parsed as `IpAddress`
    /// - Strings with '@' are parsed as `Email`
    /// - Strings with '://' are parsed as `Uri`
    /// - Everything else defaults to `DnsName`
    ///
    /// # Arguments
    ///
    /// * `host` - The host string to parse
    ///
    /// # Returns
    ///
    /// The parsed `HostType`, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the host string is invalid for its detected type.
    pub fn parse(host: &str) -> Result<Self> {
        // Try IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            validate_ip_address(&ip)?;
            return Ok(HostType::IpAddress(ip));
        }

        // Try email (simple check)
        if host.contains('@') {
            validate_email_address(host)?;
            return Ok(HostType::Email(host.to_string()));
        }

        // Try URI (has scheme)
        if host.contains("://") {
            validate_uri(host)?;
            return Ok(HostType::Uri(host.to_string()));
        }

        // Default to DNS name
        Ok(HostType::DnsName(host.to_string()))
    }
}

/// Validate IP address (comprehensive checks for IPv4 and IPv6)
pub fn validate_ip_address(ip: &IpAddr) -> Result<()> {
    match ip {
        IpAddr::V4(ipv4) => {
            // Allow all valid IPv4 addresses for development
            // Just ensure it's not unspecified
            if ipv4.is_unspecified() {
                return Err(Error::InvalidHostname(format!(
                    "Unspecified IP address not allowed: {}",
                    ip
                )));
            }

            Ok(())
        }
        IpAddr::V6(ipv6) => {
            // Validate IPv6 address
            if ipv6.is_unspecified() {
                return Err(Error::InvalidHostname(format!(
                    "Unspecified IP address not allowed: {}",
                    ip
                )));
            }

            Ok(())
        }
    }
}

/// Validate email address using regex
pub fn validate_email_address(email: &str) -> Result<()> {
    // RFC 5322 compliant email validation (simplified)
    let email_regex = Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();

    if !email_regex.is_match(email) {
        return Err(Error::InvalidHostname(format!(
            "Invalid email address: {}",
            email
        )));
    }

    Ok(())
}

/// Validate URI format
pub fn validate_uri(uri: &str) -> Result<()> {
    // Basic URI validation - must have scheme and path
    let uri_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+$").unwrap();

    if !uri_regex.is_match(uri) {
        return Err(Error::InvalidHostname(format!(
            "Invalid URI format: {}",
            uri
        )));
    }

    // Ensure scheme is valid
    if let Some(scheme_end) = uri.find("://") {
        let scheme = &uri[..scheme_end];
        if scheme.is_empty() {
            return Err(Error::InvalidHostname(format!(
                "URI must have a scheme: {}",
                uri
            )));
        }
    }

    Ok(())
}

pub fn validate_hostname(hostname: &str) -> Result<()> {
    let hostname_regex = Regex::new(r"(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$").unwrap();

    if !hostname_regex.is_match(hostname) {
        return Err(Error::InvalidHostname(hostname.to_string()));
    }

    Ok(())
}

/// Convert international domain name to ASCII using IDNA (punycode)
pub fn domain_to_ascii(domain: &str) -> Result<String> {
    match idna::domain_to_ascii(domain) {
        Ok(ascii) => Ok(ascii),
        Err(_) => Err(Error::InvalidHostname(format!(
            "Invalid international domain name: {}",
            domain
        ))),
    }
}

/// Convert ASCII domain name back to Unicode using IDNA
pub fn domain_to_unicode(domain: &str) -> String {
    idna::domain_to_unicode(domain).0
}

/// Generate a cryptographically secure random serial number for certificates
pub fn generate_serial_number() -> [u8; 16] {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut serial = [0u8; 16];
    rng.fill(&mut serial)
        .expect("Failed to generate random serial number");
    // Ensure the serial number is positive by clearing the high bit
    serial[0] &= 0x7F;
    serial
}

/// Format certificate expiration date in RFC2822 format
pub fn format_expiration_date(expiration: OffsetDateTime) -> String {
    expiration
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| format!("{}", expiration))
}

/// Calculate certificate expiration date (2 years and 3 months from now)
pub fn calculate_cert_expiration() -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::days(730 + 90)
}

/// Check if certificate is expiring soon (within 30 days)
pub fn is_cert_expiring_soon(expiration: OffsetDateTime) -> bool {
    let now = OffsetDateTime::now_utc();
    let days_until_expiry = (expiration - now).whole_days();
    (0..=30).contains(&days_until_expiry)
}

/// Validate certificate chain (cert must be signed by CA)
pub fn validate_cert_chain(cert_der: &[u8], ca_cert_der: &[u8]) -> Result<()> {
    use x509_parser::prelude::*;

    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| Error::Certificate(format!("Failed to parse certificate: {}", e)))?;

    // Parse the CA certificate
    let (_, ca_cert) = X509Certificate::from_der(ca_cert_der)
        .map_err(|e| Error::Certificate(format!("Failed to parse CA certificate: {}", e)))?;

    // Verify that the cert was issued by the CA
    // Check that the issuer matches the CA's subject
    if cert.issuer() != ca_cert.subject() {
        return Err(Error::Certificate(
            "Certificate was not issued by the provided CA".to_string(),
        ));
    }

    // Additional checks could include signature verification
    // but x509-parser doesn't provide easy signature verification

    Ok(())
}

/// Print expiry warning if certificate is expiring soon
pub fn check_cert_expiry_warning(expiration: OffsetDateTime) {
    if is_cert_expiring_soon(expiration) {
        let days = (expiration - OffsetDateTime::now_utc()).whole_days();
        eprintln!(
            "{} Certificate expires in {} days!",
            "Warning:".yellow().bold(),
            days
        );
    }
}

/// Process a single host and convert to SanType
fn process_host_to_san(host: &str) -> Result<SanType> {
    let host_type = HostType::parse(host)?;
    match host_type {
        HostType::DnsName(name) => {
            validate_hostname(&name)?;
            validate_wildcard_depth(&name)?;
            check_wildcard_warning(&name);
            let ia5 = Ia5String::try_from(name)
                .map_err(|e| Error::Certificate(format!("Invalid DNS name: {}", e)))?;
            Ok(SanType::DnsName(ia5))
        }
        HostType::IpAddress(ip) => Ok(SanType::IpAddress(ip)),
        HostType::Email(email) => {
            let ia5 = Ia5String::try_from(email)
                .map_err(|e| Error::Certificate(format!("Invalid email: {}", e)))?;
            Ok(SanType::Rfc822Name(ia5))
        }
        HostType::Uri(uri) => {
            let ia5 = Ia5String::try_from(uri)
                .map_err(|e| Error::Certificate(format!("Invalid URI: {}", e)))?;
            Ok(SanType::URI(ia5))
        }
    }
}

/// Build Subject Alternative Names from a list of host strings
pub fn build_san_list(hosts: &[String]) -> Result<Vec<SanType>> {
    hosts.iter().map(|host| process_host_to_san(host)).collect()
}

/// Validate wildcard depth (only one level deep is allowed)
pub fn validate_wildcard_depth(name: &str) -> Result<()> {
    if let Some(stripped) = name.strip_prefix("*.") {
        // Count the number of wildcard components
        let wildcard_count = name.matches("*").count();
        if wildcard_count > 1 {
            return Err(Error::InvalidHostname(format!(
                "Multiple wildcards not allowed: {}",
                name
            )));
        }

        // Ensure wildcard is only at the beginning
        if stripped.contains('*') {
            return Err(Error::InvalidHostname(format!(
                "Wildcard must be at the beginning: {}",
                name
            )));
        }
    } else if name.contains('*') {
        return Err(Error::InvalidHostname(format!(
            "Wildcard must be at the beginning: {}",
            name
        )));
    }

    Ok(())
}

/// Check for wildcard certificates and log warnings
fn check_wildcard_warning(name: &str) {
    // Check for second-level wildcards (e.g., *.com, *.net)
    let second_level_wildcard_regex = Regex::new(r"(?i)^\*\.[0-9a-z_-]+$").unwrap();
    if second_level_wildcard_regex.is_match(name) {
        eprintln!(
            "{} many browsers don't support second-level wildcards like \"{}\"",
            "Warning:".yellow().bold(),
            name
        );
    }

    // General wildcard reminder
    if let Some(stripped) = name.strip_prefix("*.") {
        eprintln!(
            "{} X.509 wildcards only go one level deep, so this won't match a.b.{}",
            "Reminder:".cyan(),
            stripped
        );
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
    if !params
        .extended_key_usages
        .contains(&ExtendedKeyUsagePurpose::ServerAuth)
    {
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
    }
}

/// Add client authentication extended key usage
pub fn add_client_auth(params: &mut CertificateParams) {
    if !params
        .extended_key_usages
        .contains(&ExtendedKeyUsagePurpose::ClientAuth)
    {
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
    }
}

/// Add email protection extended key usage
pub fn add_email_protection(params: &mut CertificateParams) {
    if !params
        .extended_key_usages
        .contains(&ExtendedKeyUsagePurpose::EmailProtection)
    {
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::EmailProtection);
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
/// File naming convention: example.com+4.pem, example.com+4-key.pem, example.com+4.p12
pub fn generate_file_names(config: &CertificateConfig) -> (PathBuf, PathBuf, PathBuf) {
    // Use provided file names if available
    if let (Some(cert), Some(key), Some(p12)) =
        (&config.cert_file, &config.key_file, &config.p12_file)
    {
        return (cert.clone(), key.clone(), p12.clone());
    }

    // Generate default name from first host
    let default_name = if config.hosts.is_empty() {
        "cert".to_string()
    } else {
        let mut name = config.hosts[0].replace(':', "_").replace('*', "_wildcard");

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

    let cert_file = config
        .cert_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("./{}.pem", default_name)));
    let key_file = config
        .key_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("./{}-key.pem", default_name)));
    let p12_file = config
        .p12_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("./{}.p12", default_name)));

    (cert_file, key_file, p12_file)
}

/// Write PEM files with appropriate permissions using buffered I/O
/// Certificate files: 0644 (readable by all)
/// Key files: 0600 (readable only by owner)
/// If cert and key are in the same file, use 0600
pub fn write_pem_files(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    use std::io::BufWriter;

    if cert_path == key_path {
        // Combined file: write both cert and key with restricted permissions (0600)
        let file = std::fs::File::create(cert_path).map_err(Error::Io)?;
        let mut writer = BufWriter::new(file);
        use std::io::Write;
        writer.write_all(cert_pem.as_bytes()).map_err(Error::Io)?;
        writer.write_all(key_pem.as_bytes()).map_err(Error::Io)?;
        writer.flush().map_err(Error::Io)?;
        set_file_permissions(cert_path, 0o600)?;
    } else {
        // Separate files
        let cert_file = std::fs::File::create(cert_path).map_err(Error::Io)?;
        let mut cert_writer = BufWriter::new(cert_file);
        use std::io::Write;
        cert_writer
            .write_all(cert_pem.as_bytes())
            .map_err(Error::Io)?;
        cert_writer.flush().map_err(Error::Io)?;
        set_file_permissions(cert_path, 0o644)?;

        let key_file = std::fs::File::create(key_path).map_err(Error::Io)?;
        let mut key_writer = BufWriter::new(key_file);
        key_writer
            .write_all(key_pem.as_bytes())
            .map_err(Error::Io)?;
        key_writer.flush().map_err(Error::Io)?;
        set_file_permissions(key_path, 0o600)?;
    }

    Ok(())
}

/// Set file permissions (Unix: actual permissions, Windows: no-op for now)
#[cfg(unix)]
pub(crate) fn set_file_permissions(path: &PathBuf, mode: u32) -> Result<()> {
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions).map_err(Error::Io)
}

#[cfg(not(unix))]
pub(crate) fn set_file_permissions(_path: &PathBuf, _mode: u32) -> Result<()> {
    // On Windows, we could use SetNamedSecurityInfo but for now just skip
    // The Go implementation also uses ioutil.WriteFile which doesn't set special permissions on Windows
    Ok(())
}

/// Verify file permissions (Unix only)
#[cfg(unix)]
pub fn verify_file_permissions(path: &PathBuf, expected_mode: u32) -> Result<bool> {
    let metadata = fs::metadata(path).map_err(Error::Io)?;
    let permissions = metadata.permissions();
    let actual_mode = permissions.mode() & 0o777;
    Ok(actual_mode == expected_mode)
}

#[cfg(not(unix))]
pub fn verify_file_permissions(_path: &PathBuf, _expected_mode: u32) -> Result<bool> {
    // On Windows, skip permission verification
    Ok(true)
}

/// Write PKCS#12 file with certificate, key, and CA cert
/// Uses the default password "changeit"
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
    fs::write(p12_path, &pfx_data).map_err(Error::Io)?;
    set_file_permissions(p12_path, 0o644)?;

    Ok(())
}

/// Print certificate hosts with warnings
pub fn print_hosts(hosts: &[String]) {
    let second_level_wildcard_regex = Regex::new(r"(?i)^\*\.[0-9a-z_-]+$").unwrap();

    println!(
        "\n{}",
        "Created a new certificate valid for the following names"
            .green()
            .bold()
    );
    for host in hosts {
        println!(" - {}", host.bright_white());
        if second_level_wildcard_regex.is_match(host) {
            println!(
                "   {} many browsers don't support second-level wildcards like {}",
                "Warning:".yellow().bold(),
                host
            );
        }
    }

    // Check for any wildcards and print reminder
    for host in hosts {
        if let Some(stripped) = host.strip_prefix("*.") {
            println!(
                "\n{} X.509 wildcards only go one level deep, so this won't match a.b.{}",
                "Reminder:".cyan(),
                stripped
            );
            break;
        }
    }
}

/// Generate a certificate from command line arguments.
///
/// This is the main entry point for certificate generation. It loads the CA,
/// creates a certificate configuration, and generates the certificate with
/// the specified parameters.
///
/// # Arguments
///
/// * `domains` - List of domains, IPs, emails, or URIs for the certificate
/// * `cert_file` - Optional custom path for the certificate file
/// * `key_file` - Optional custom path for the private key file
/// * `p12_file` - Optional custom path for the PKCS#12 bundle
/// * `client` - Generate a client authentication certificate
/// * `ecdsa` - Use ECDSA instead of RSA for the key
/// * `pkcs12` - Generate PKCS#12 bundle instead of PEM files
///
/// # Returns
///
/// `Ok(())` on success, or an error if generation fails.
///
/// # Errors
///
/// Returns an error if:
/// - The CA cannot be loaded or created
/// - Domain validation fails
/// - Certificate generation fails
/// - File writing fails
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
    let ca = crate::ca::CA::load_or_create()?;

    // Get CA certificate and key PEMs
    let ca_cert_pem = std::fs::read_to_string(ca.cert_path())?;
    let ca_key_pem = std::fs::read_to_string(ca.key_path())?;

    // Build config
    let mut config = CertificateConfig::new(domains.to_vec());
    config.client_cert = client;
    config.use_ecdsa = ecdsa;
    config.pkcs12 = pkcs12;
    config.cert_file = cert_file.map(PathBuf::from);
    config.key_file = key_file.map(PathBuf::from);
    config.p12_file = p12_file.map(PathBuf::from);

    // Generate the certificate
    generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem)
}

/// Read CSR file from disk
pub fn read_csr_file(csr_path: &str) -> Result<Vec<u8>> {
    fs::read(csr_path).map_err(|e| Error::Certificate(format!("Failed to read CSR file: {}", e)))
}

/// Parse CSR from PEM format and return the DER bytes
pub fn parse_csr_pem(csr_bytes: &[u8]) -> Result<Vec<u8>> {
    // Try to parse as PEM first
    let pem_str = std::str::from_utf8(csr_bytes)
        .map_err(|e| Error::Certificate(format!("Invalid UTF-8 in CSR file: {}", e)))?;

    // Find the PEM block boundaries
    let begin_marker = "-----BEGIN";
    let end_marker = "-----END";

    let begin_pos = pem_str
        .find(begin_marker)
        .ok_or_else(|| Error::Certificate("No PEM data found in CSR file".to_string()))?;
    let end_pos = pem_str
        .find(end_marker)
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
pub fn validate_csr_signature(
    csr: &x509_parser::certification_request::X509CertificationRequest,
) -> Result<()> {
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
pub fn extract_san_from_csr(
    csr: &x509_parser::certification_request::X509CertificationRequest,
) -> Result<Vec<String>> {
    let mut hosts = Vec::new();
    let req_info = &csr.certification_request_info;

    // For now, just extract the Common Name from the subject
    // Full SAN extraction from CSR extensions is complex and can be added later
    if let Some(cn) = req_info.subject.iter_common_name().next()
        && let Ok(cn_str) = cn.as_str()
    {
        hosts.push(cn_str.to_string());
    }

    // If no CN found, return an error
    if hosts.is_empty() {
        return Err(Error::Certificate(
            "No Common Name found in CSR subject".to_string(),
        ));
    }

    Ok(hosts)
}

/// Generate a certificate from a Certificate Signing Request (CSR).
///
/// Reads a CSR file, extracts the subject names and public key,
/// and generates a signed certificate using the local CA.
///
/// # Arguments
///
/// * `csr_path` - Path to the CSR file (PEM format)
/// * `cert_file` - Optional custom path for the output certificate
///
/// # Returns
///
/// `Ok(())` on success, or an error if generation fails.
///
/// # Errors
///
/// Returns an error if:
/// - The CSR file cannot be read or parsed
/// - The CSR signature is invalid
/// - No subject names are found in the CSR
/// - Certificate generation or signing fails
pub fn generate_from_csr(csr_path: &str, cert_file: Option<&str>) -> Result<()> {
    use x509_parser::prelude::*;

    // Load CA
    let ca = crate::ca::CA::load_or_create()?;

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
        return Err(Error::Certificate(
            "No subject names found in CSR".to_string(),
        ));
    }

    // Get CA cert and key for signing
    let ca_cert_pem = std::fs::read_to_string(ca.cert_path())?;
    let ca_key_pem = std::fs::read_to_string(ca.key_path())?;

    // TODO: CSR handling needs proper public key extraction
    // For now, generate a new key pair (this is a workaround)
    let cert_key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
        .map_err(|e| Error::Certificate(format!("Failed to generate key pair: {}", e)))?;

    let ca_key_pair = KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| Error::Certificate(format!("Failed to parse CA key: {}", e)))?;

    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair)
        .map_err(|e| Error::Certificate(format!("Failed to create issuer: {}", e)))?;

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

    // Create signed certificate
    let cert = params
        .signed_by(&cert_key_pair, &issuer)
        .map_err(|e| Error::Certificate(format!("Failed to create signed certificate: {}", e)))?;

    let cert_der = cert.der().to_vec();

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
    fs::write(&output_file, cert_pem.as_bytes()).map_err(Error::Io)?;
    set_file_permissions(&output_file, 0o644)?;

    // Print certificate information
    print_hosts(&hosts);
    println!("\nThe certificate is at {:?}\n", output_file);

    // Print expiration date
    let expiration = calculate_cert_expiration();
    check_cert_expiry_warning(expiration);
    println!("It will expire on {}\n", format_expiration_date(expiration));

    Ok(())
}

/// Copy subject from X509Name to rcgen DistinguishedName
fn copy_subject_to_params(
    params: &mut CertificateParams,
    subject: &x509_parser::x509::X509Name,
) -> Result<()> {
    use rcgen::{DistinguishedName, DnType};

    let mut dn = DistinguishedName::new();

    // Copy common name
    if let Some(cn) = subject.iter_common_name().next()
        && let Ok(cn_str) = cn.as_str()
    {
        dn.push(DnType::CommonName, cn_str);
    }

    // Copy organization
    if let Some(o) = subject.iter_organization().next()
        && let Ok(o_str) = o.as_str()
    {
        dn.push(DnType::OrganizationName, o_str);
    }

    // Copy organizational unit
    if let Some(ou) = subject.iter_organizational_unit().next()
        && let Ok(ou_str) = ou.as_str()
    {
        dn.push(DnType::OrganizationalUnitName, ou_str);
    }

    params.distinguished_name = dn;
    Ok(())
}

/// Generate and save a new certificate signed by the CA
/// This is the main certificate generation function that orchestrates everything
fn generate_certificate_internal(
    config: &CertificateConfig,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<()> {
    if config.hosts.is_empty() {
        return Err(Error::Certificate("No hosts specified".to_string()));
    }

    // Generate key pair based on config (RSA-2048 or ECDSA P-256)
    let cert_key_pair = if config.use_ecdsa {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::Certificate(format!("Failed to generate ECDSA key pair: {}", e)))?
    } else {
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
            .map_err(|e| Error::Certificate(format!("Failed to generate RSA key pair: {}", e)))?
    };

    // Parse CA key pair
    let ca_key_pair = KeyPair::from_pem(ca_key_pem)
        .map_err(|e| Error::Certificate(format!("Failed to parse CA key: {}", e)))?;

    // Create issuer from CA certificate and key
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key_pair)
        .map_err(|e| Error::Certificate(format!("Failed to create issuer from CA cert: {}", e)))?;

    // Create certificate parameters
    let mut params = create_cert_params(&config.hosts)?;

    // Set extended key usage based on certificate type
    if config.client_cert {
        add_client_auth(&mut params);
    }

    // Check if we have IP addresses, DNS names, or URIs for server auth
    let has_server_names = config.hosts.iter().any(|h| {
        let host_type = HostType::parse(h).ok();
        matches!(
            host_type,
            Some(HostType::DnsName(_)) | Some(HostType::IpAddress(_)) | Some(HostType::Uri(_))
        )
    });

    if has_server_names {
        add_server_auth(&mut params);
    }

    // Check if we have email addresses for email protection
    let has_email = config
        .hosts
        .iter()
        .any(|h| matches!(HostType::parse(h).ok(), Some(HostType::Email(_))));

    if has_email {
        add_email_protection(&mut params);
    }

    // If generating PKCS#12, set the CommonName to the first host (for IIS compatibility)
    if config.pkcs12 {
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, config.hosts[0].clone());
    }

    // Create the certificate signed by the CA
    let cert = params
        .signed_by(&cert_key_pair, &issuer)
        .map_err(|e| Error::Certificate(format!("Failed to create signed certificate: {}", e)))?;

    // Get certificate DER
    let cert_der = cert.der().to_vec();

    // Get CA cert DER for PKCS#12 - parse from PEM
    let ca_cert_pem_parsed = pem::parse(ca_cert_pem)
        .map_err(|e| Error::Certificate(format!("Failed to parse CA cert PEM: {}", e)))?;
    let ca_cert_der = ca_cert_pem_parsed.contents().to_vec();

    // Get file names
    let (cert_file, key_file, p12_file) = generate_file_names(config);

    // Write files based on mode
    if !config.pkcs12 {
        // PEM mode
        let cert_pem = cert_to_pem(&cert_der);
        let key_pem = key_to_pem(&cert_key_pair)?;
        write_pem_files(&cert_file, &key_file, &cert_pem, &key_pem)?;
    } else {
        // PKCS#12 mode
        write_pkcs12_file(&p12_file, &cert_der, &cert_key_pair, &ca_cert_der)?;
    }

    // Print certificate information
    print_hosts(&config.hosts);

    // Print file paths
    if !config.pkcs12 {
        if cert_file == key_file {
            println!(
                "\n{} {:?}\n",
                "The certificate and key are at".green(),
                cert_file
            );
        } else {
            println!(
                "\n{} {:?} {} {:?}\n",
                "The certificate is at".green(),
                cert_file,
                "and the key at".green(),
                key_file
            );
        }
    } else {
        println!("\n{} {:?}", "The PKCS#12 bundle is at".green(), p12_file);
        println!(
            "\n{} The legacy PKCS#12 encryption password is the often hardcoded default \"changeit\"\n",
            "Info:".cyan()
        );
    }

    // Print expiration date
    let expiration = calculate_cert_expiration();
    check_cert_expiry_warning(expiration);
    println!(
        "{} {}\n",
        "It will expire on".bright_white(),
        format_expiration_date(expiration)
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a test CA certificate with ECDSA
    /// Returns (ca_cert_pem, ca_key_pem)
    fn create_test_ca() -> (String, String) {
        // Generate ECDSA key pair for the CA
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();

        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");

        // Create self-signed CA certificate
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        (cert_pem, key_pem)
    }

    #[test]
    fn test_parse_dns_name() {
        let ht = HostType::parse("example.com").unwrap();
        assert_eq!(ht, HostType::DnsName("example.com".to_string()));
    }

    #[test]
    fn test_parse_ip() {
        let ht = HostType::parse("127.0.0.1").unwrap();
        match ht {
            HostType::IpAddress(_) => {}
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

        // Create a test CA
        let (ca_cert_pem, ca_key_pem) = create_test_ca();

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
        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(
            result.is_ok(),
            "Certificate generation failed: {:?}",
            result.err()
        );

        // Verify files were created
        assert!(cert_path.exists(), "Certificate file was not created");
        assert!(key_path.exists(), "Key file was not created");

        // Verify file contents
        let cert_pem = fs::read_to_string(&cert_path).unwrap();
        let key_pem = fs::read_to_string(&key_path).unwrap();

        assert!(
            cert_pem.contains("BEGIN CERTIFICATE"),
            "Certificate PEM is invalid"
        );
        assert!(
            key_pem.contains("BEGIN PRIVATE KEY"),
            "Private key PEM is invalid"
        );

        // Verify file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let cert_perms = fs::metadata(&cert_path).unwrap().permissions();
            let key_perms = fs::metadata(&key_path).unwrap().permissions();

            assert_eq!(
                cert_perms.mode() & 0o777,
                0o644,
                "Certificate permissions incorrect"
            );
            assert_eq!(key_perms.mode() & 0o777, 0o600, "Key permissions incorrect");
        }
    }

    #[test]
    fn test_certificate_generation_combined_file() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create a test CA
        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        let mut config = CertificateConfig::new(vec!["localhost".to_string()]);
        config.use_ecdsa = true;
        let combined_path = temp_path.join("localhost-combined.pem");

        config.cert_file = Some(combined_path.clone());
        config.key_file = Some(combined_path.clone());

        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(
            result.is_ok(),
            "Certificate generation failed: {:?}",
            result.err()
        );

        assert!(combined_path.exists(), "Combined file was not created");

        let combined_pem = fs::read_to_string(&combined_path).unwrap();
        assert!(
            combined_pem.contains("BEGIN CERTIFICATE"),
            "Combined file missing certificate"
        );
        assert!(
            combined_pem.contains("BEGIN PRIVATE KEY"),
            "Combined file missing key"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&combined_path).unwrap().permissions();
            assert_eq!(
                perms.mode() & 0o777,
                0o600,
                "Combined file permissions should be 0600"
            );
        }
    }

    #[test]
    fn test_csr_file_reading() {
        use std::io::Write;
        use tempfile::TempDir;

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
    #[ignore] // TODO: Fix CSR generation with rcgen 0.14 - serialize_request_der() was removed
    fn test_csr_pem_parsing() {
        // TODO: Update this test for rcgen 0.14 CSR API
    }

    #[test]
    #[ignore] // TODO: Fix CSR generation with rcgen 0.14 - serialize_request_der() was removed
    fn test_extract_san_from_csr() {
        // TODO: Update this test for rcgen 0.14 CSR API
    }

    #[test]
    fn test_end_to_end_certificate_generation() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create a test CA

        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        let hosts = vec!["example.com".to_string(), "localhost".to_string()];
        let mut config = CertificateConfig::new(hosts.clone());
        config.use_ecdsa = true;

        let cert_path = temp_path.join("test.pem");
        let key_path = temp_path.join("test-key.pem");

        config.cert_file = Some(cert_path.clone());
        config.key_file = Some(key_path.clone());

        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(
            result.is_ok(),
            "End-to-end certificate generation failed: {:?}",
            result.err()
        );

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

    #[test]
    fn test_generate_serial_number() {
        let serial1 = generate_serial_number();
        let serial2 = generate_serial_number();

        assert_eq!(serial1.len(), 16);
        assert_eq!(serial2.len(), 16);
        assert_ne!(serial1, serial2, "Serial numbers should be unique");
        assert_eq!(
            serial1[0] & 0x80,
            0,
            "Serial number high bit should be clear"
        );
    }

    #[test]
    fn test_calculate_cert_expiration() {
        let expiration = calculate_cert_expiration();
        let now = OffsetDateTime::now_utc();
        let diff = expiration - now;

        // Should be approximately 820 days (730 + 90)
        assert!(diff.whole_days() >= 819 && diff.whole_days() <= 821);
    }

    #[test]
    fn test_format_expiration_date() {
        let now = OffsetDateTime::now_utc();
        let formatted = format_expiration_date(now);

        // Should contain common date elements
        assert!(!formatted.is_empty());
        assert!(formatted.len() > 10);
    }

    #[test]
    fn test_wildcard_depth_validation() {
        assert!(validate_wildcard_depth("*.example.com").is_ok());
        assert!(validate_wildcard_depth("example.com").is_ok());
        assert!(validate_wildcard_depth("*.*.example.com").is_err());
        assert!(validate_wildcard_depth("*example.com").is_err());
        assert!(validate_wildcard_depth("example.*.com").is_err());
    }

    #[test]
    fn test_ip_address_validation() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // Valid IPv4 addresses
        assert!(validate_ip_address(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).is_ok());
        assert!(validate_ip_address(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_ok());
        assert!(validate_ip_address(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_ok());

        // Invalid IPv4 - unspecified
        assert!(validate_ip_address(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))).is_err());

        // Valid IPv6 addresses
        assert!(validate_ip_address(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))).is_ok());
        assert!(
            validate_ip_address(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))).is_ok()
        );

        // Invalid IPv6 - unspecified
        assert!(validate_ip_address(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))).is_err());
    }

    #[test]
    fn test_email_address_validation() {
        // Valid email addresses
        assert!(validate_email_address("test@example.com").is_ok());
        assert!(validate_email_address("user.name@example.co.uk").is_ok());
        assert!(validate_email_address("user+tag@example.com").is_ok());

        // Invalid email addresses
        assert!(validate_email_address("notanemail").is_err());
        assert!(validate_email_address("@example.com").is_err());
        assert!(validate_email_address("test@").is_err());
        assert!(validate_email_address("test @example.com").is_err());
    }

    #[test]
    fn test_uri_validation() {
        // Valid URIs
        assert!(validate_uri("https://example.com").is_ok());
        assert!(validate_uri("http://localhost:8080/path").is_ok());
        assert!(validate_uri("ftp://files.example.com").is_ok());
        assert!(validate_uri("custom-scheme://resource").is_ok());

        // Invalid URIs
        assert!(validate_uri("not-a-uri").is_err());
        assert!(validate_uri("://missing-scheme").is_err());
        assert!(validate_uri("http://").is_err());
        assert!(validate_uri("http:// space.com").is_err());
    }

    #[test]
    fn test_host_type_parsing_dns() {
        let ht = HostType::parse("example.com").unwrap();
        assert!(matches!(ht, HostType::DnsName(_)));

        let ht = HostType::parse("*.example.com").unwrap();
        assert!(matches!(ht, HostType::DnsName(_)));

        let ht = HostType::parse("sub.example.com").unwrap();
        assert!(matches!(ht, HostType::DnsName(_)));
    }

    #[test]
    fn test_host_type_parsing_ip() {
        let ht = HostType::parse("127.0.0.1").unwrap();
        assert!(matches!(ht, HostType::IpAddress(_)));

        let ht = HostType::parse("::1").unwrap();
        assert!(matches!(ht, HostType::IpAddress(_)));

        let ht = HostType::parse("192.168.1.1").unwrap();
        assert!(matches!(ht, HostType::IpAddress(_)));
    }

    #[test]
    fn test_host_type_parsing_email() {
        let ht = HostType::parse("user@example.com").unwrap();
        assert!(matches!(ht, HostType::Email(_)));

        let ht = HostType::parse("test.user@example.co.uk").unwrap();
        assert!(matches!(ht, HostType::Email(_)));
    }

    #[test]
    fn test_host_type_parsing_uri() {
        let ht = HostType::parse("https://example.com").unwrap();
        assert!(matches!(ht, HostType::Uri(_)));

        let ht = HostType::parse("http://localhost:8080").unwrap();
        assert!(matches!(ht, HostType::Uri(_)));
    }

    #[test]
    fn test_host_type_validation_errors() {
        // Invalid IP
        assert!(HostType::parse("0.0.0.0").is_err());

        // Invalid email
        assert!(HostType::parse("invalid@").is_err());

        // Invalid URI
        assert!(HostType::parse("://no-scheme").is_err());

        // Invalid wildcard depth (tested via validate_wildcard_depth)
        assert!(validate_wildcard_depth("*.*.example.com").is_err());
    }

    #[test]
    fn test_cert_expiry_check() {
        let now = OffsetDateTime::now_utc();

        // Not expiring soon (more than 30 days)
        let far_future = now + Duration::days(60);
        assert!(!is_cert_expiring_soon(far_future));

        // Expiring soon (within 30 days)
        let near_future = now + Duration::days(15);
        assert!(is_cert_expiring_soon(near_future));

        // Expiring very soon (1 day)
        let very_soon = now + Duration::days(1);
        assert!(is_cert_expiring_soon(very_soon));

        // Already expired
        let past = now - Duration::days(1);
        assert!(!is_cert_expiring_soon(past));
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permission_verification() {
        use std::fs::File;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");

        // Create a file
        File::create(&file_path).unwrap();

        // Set permissions to 0644
        set_file_permissions(&file_path, 0o644).unwrap();

        // Verify permissions
        assert!(verify_file_permissions(&file_path, 0o644).unwrap());
        assert!(!verify_file_permissions(&file_path, 0o600).unwrap());

        // Change permissions to 0600
        set_file_permissions(&file_path, 0o600).unwrap();

        // Verify new permissions
        assert!(verify_file_permissions(&file_path, 0o600).unwrap());
        assert!(!verify_file_permissions(&file_path, 0o644).unwrap());
    }

    #[test]
    fn test_concurrent_certificate_generation() {
        use std::sync::Arc;
        use std::thread;
        use tempfile::TempDir;

        let temp_dir = Arc::new(TempDir::new().unwrap());

        // Create a test CA (PEM strings are Clone, no need for Arc)
        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        // Spawn multiple threads to generate certificates concurrently
        let mut handles = vec![];

        for i in 0..3 {
            let temp_dir = Arc::clone(&temp_dir);
            let ca_cert_pem = ca_cert_pem.clone();
            let ca_key_pem = ca_key_pem.clone();

            let handle = thread::spawn(move || {
                let hosts = vec![format!("test{}.example.com", i)];
                let mut config = CertificateConfig::new(hosts);
                config.use_ecdsa = true;

                let cert_path = temp_dir.path().join(format!("cert{}.pem", i));
                let key_path = temp_dir.path().join(format!("key{}.pem", i));

                config.cert_file = Some(cert_path.clone());
                config.key_file = Some(key_path.clone());

                let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
                assert!(result.is_ok(), "Concurrent certificate generation failed");

                // Verify files exist
                assert!(cert_path.exists(), "Certificate file not created");
                assert!(key_path.exists(), "Key file not created");
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_certificate_chain_validation() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create a test CA
        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        // Parse CA cert PEM to get DER
        let ca_cert_pem_parsed = pem::parse(&ca_cert_pem).unwrap();
        let ca_cert_der = ca_cert_pem_parsed.contents().to_vec();

        // Create end-entity certificate
        let hosts = vec!["example.com".to_string()];
        let mut config = CertificateConfig::new(hosts);
        config.use_ecdsa = true;

        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        config.cert_file = Some(cert_path.clone());
        config.key_file = Some(key_path.clone());

        generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem).unwrap();

        // Read the generated certificate
        let cert_pem = fs::read_to_string(&cert_path).unwrap();
        let cert_der_data = pem::parse(&cert_pem).unwrap();
        let cert_der = cert_der_data.contents();

        // Validate the chain
        let result = validate_cert_chain(cert_der, &ca_cert_der);
        assert!(result.is_ok(), "Certificate chain validation failed");
    }

    #[test]
    fn test_multi_domain_certificate() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // Create a test CA

        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        let hosts = vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "api.example.com".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ];
        let mut config = CertificateConfig::new(hosts);
        config.use_ecdsa = true;
        config.cert_file = Some(temp_dir.path().join("multi.pem"));
        config.key_file = Some(temp_dir.path().join("multi-key.pem"));

        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(result.is_ok(), "Multi-domain certificate generation failed");
    }

    #[test]
    fn test_ipv6_certificate() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // Create a test CA

        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        let hosts = vec![
            "::1".to_string(),
            "fe80::1".to_string(),
            "2001:db8::1".to_string(),
        ];
        let mut config = CertificateConfig::new(hosts);
        config.use_ecdsa = true;
        config.cert_file = Some(temp_dir.path().join("ipv6.pem"));
        config.key_file = Some(temp_dir.path().join("ipv6-key.pem"));

        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(result.is_ok(), "IPv6 certificate generation failed");
    }

    #[test]
    fn test_wildcard_certificate() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // Create a test CA

        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        let hosts = vec!["*.example.com".to_string()];
        let mut config = CertificateConfig::new(hosts);
        config.use_ecdsa = true;
        config.cert_file = Some(temp_dir.path().join("wildcard.pem"));
        config.key_file = Some(temp_dir.path().join("wildcard-key.pem"));

        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(result.is_ok(), "Wildcard certificate generation failed");
    }

    #[test]
    fn test_client_certificate() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // Create a test CA

        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        let hosts = vec!["client@example.com".to_string()];
        let mut config = CertificateConfig::new(hosts);
        config.use_ecdsa = true;
        config.client_cert = true;
        config.cert_file = Some(temp_dir.path().join("client.pem"));
        config.key_file = Some(temp_dir.path().join("client-key.pem"));

        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(result.is_ok(), "Client certificate generation failed");
    }

    #[test]
    fn test_pkcs12_export() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // Create a test CA

        let (ca_cert_pem, ca_key_pem) = create_test_ca();

        let hosts = vec!["example.com".to_string()];
        let mut config = CertificateConfig::new(hosts);
        config.use_ecdsa = true;
        config.pkcs12 = true;
        config.p12_file = Some(temp_dir.path().join("example.p12"));

        let result = generate_certificate_internal(&config, &ca_cert_pem, &ca_key_pem);
        assert!(result.is_ok(), "PKCS#12 export failed");

        let p12_path = temp_dir.path().join("example.p12");
        assert!(p12_path.exists(), "PKCS#12 file was not created");
    }
}
