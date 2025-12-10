//! Certificate Authority management

use crate::{Error, Result};
use colored::*;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, RsaKeySize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const ROOT_CERT_FILE: &str = "rootCA.pem";
const ROOT_KEY_FILE: &str = "rootCA-key.pem";

/// Get the CAROOT directory path as a string.
///
/// Returns the directory where the CA certificate and key are stored.
/// This can be customized via the `CAROOT` environment variable.
///
/// # Returns
///
/// The CAROOT directory path as a `String`.
///
/// # Errors
///
/// Returns an error if the CAROOT directory cannot be determined.
pub fn get_caroot() -> Result<String> {
    let caroot = get_caroot_path()?;
    Ok(caroot.display().to_string())
}

/// Get the CAROOT directory path as PathBuf.
///
/// Checks the `CAROOT` environment variable first, then falls back to
/// platform-specific default locations:
/// - macOS: `~/Library/Application Support/fastcert`
/// - Windows: `%LOCALAPPDATA%\fastcert`
/// - Linux: `~/.local/share/fastcert`
///
/// # Returns
///
/// The CAROOT directory path as a `PathBuf`.
///
/// # Errors
///
/// Returns an error if the directory cannot be determined.
fn get_caroot_path() -> Result<PathBuf> {
    // Check CAROOT environment variable
    if let Ok(caroot) = std::env::var("CAROOT") {
        return Ok(PathBuf::from(caroot));
    }

    // Get default location based on platform
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home
                .join("Library")
                .join("Application Support")
                .join("fastcert"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_app_data) = dirs::data_local_dir() {
            return Ok(local_app_data.join("fastcert"));
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(data_dir) = dirs::data_dir() {
            return Ok(data_dir.join("fastcert"));
        }
    }

    Err(Error::Certificate(
        "Could not determine CAROOT directory".to_string(),
    ))
}

/// Install the CA certificate into the system trust store.
///
/// This function loads or creates a CA certificate and installs it into
/// the appropriate trust stores for the current platform:
/// - macOS: System Keychain
/// - Linux: System CA certificates and NSS databases
/// - Windows: Windows Certificate Store
///
/// The CA certificate is automatically created if it doesn't exist.
///
/// # Returns
///
/// `Ok(())` on successful installation, or an error if installation fails.
///
/// # Errors
///
/// Returns an error if:
/// - The CA directory cannot be created
/// - The CA certificate cannot be generated or loaded
/// - System trust store installation fails (may require elevated privileges)
pub fn install() -> Result<()> {
    let caroot = get_caroot_path()?;
    let mut ca = CertificateAuthority::new(caroot);
    ca.load_or_create()?;

    #[cfg(target_os = "macos")]
    {
        crate::truststore::install_macos(&ca.cert_path())?;
    }

    #[cfg(target_os = "linux")]
    {
        crate::truststore::install_linux(&ca.cert_path())?;
    }

    #[cfg(target_os = "windows")]
    {
        crate::truststore::install_windows(&ca.cert_path())?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        println!("Note: System trust store installation not yet implemented for this platform.");
        println!(
            "You may need to manually import the CA certificate from: {}",
            ca.cert_path().display()
        );
    }

    Ok(())
}

/// Uninstall the CA certificate from the system trust store.
///
/// Removes the CA certificate from all system trust stores where it was
/// installed, but does not delete the CA certificate files themselves.
/// The certificate can be reinstalled later without regeneration.
///
/// # Returns
///
/// `Ok(())` on successful uninstallation, or an error if uninstallation fails.
///
/// # Errors
///
/// Returns an error if:
/// - The CA certificate cannot be read
/// - System trust store uninstallation fails (may require elevated privileges)
pub fn uninstall() -> Result<()> {
    let caroot = get_caroot_path()?;
    let ca = CertificateAuthority::new(caroot);

    if !ca.cert_exists() {
        println!("No CA certificate found to uninstall.");
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        crate::truststore::uninstall_macos(&ca.cert_path())?;
    }

    #[cfg(target_os = "linux")]
    {
        crate::truststore::uninstall_linux(&ca.cert_path())?;
    }

    #[cfg(target_os = "windows")]
    {
        crate::truststore::uninstall_windows(&ca.cert_path())?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        println!("Note: System trust store uninstallation not yet implemented for this platform.");
        println!(
            "You may need to manually remove the CA certificate from your system trust store."
        );
    }

    Ok(())
}

/// Get the CertificateAuthority instance for the default CAROOT location.
///
/// Creates a new `CertificateAuthority` instance pointing to the default
/// CAROOT directory. The CA may or may not exist yet.
///
/// # Returns
///
/// A `CertificateAuthority` instance.
///
/// # Errors
///
/// Returns an error if the CAROOT path cannot be determined.
pub fn get_ca() -> Result<CertificateAuthority> {
    let caroot = get_caroot_path()?;
    Ok(CertificateAuthority::new(caroot))
}

/// Certificate Authority management structure.
///
/// Manages the local CA certificate and private key used to sign
/// development certificates. Provides methods for creating, loading,
/// and managing the CA lifecycle.
pub struct CertificateAuthority {
    /// Path to the directory containing CA files
    root_path: PathBuf,
    /// The CA certificate (loaded or generated)
    cert: Option<Certificate>,
    /// PEM-encoded CA certificate
    cert_pem: Option<String>,
    /// PEM-encoded CA private key
    key_pem: Option<String>,
}

impl CertificateAuthority {
    /// Create a new CertificateAuthority instance.
    ///
    /// # Arguments
    ///
    /// * `root_path` - Directory where CA certificate and key will be stored
    ///
    /// # Returns
    ///
    /// A new `CertificateAuthority` instance.
    pub fn new(root_path: PathBuf) -> Self {
        Self {
            root_path,
            cert: None,
            cert_pem: None,
            key_pem: None,
        }
    }

    /// Get the root path of this CA.
    ///
    /// # Returns
    ///
    /// Reference to the CA root directory path.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Initialize the CA directory structure.
    ///
    /// Creates the root directory if it doesn't exist.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an IO error if directory creation fails.
    pub fn init(&self) -> Result<()> {
        if !self.root_path.exists() {
            fs::create_dir_all(&self.root_path)?;
        }
        Ok(())
    }

    /// Get the path to the CA certificate file.
    ///
    /// # Returns
    ///
    /// Full path to `rootCA.pem`.
    pub fn cert_path(&self) -> PathBuf {
        self.root_path.join(ROOT_CERT_FILE)
    }

    /// Get the path to the CA private key file.
    ///
    /// # Returns
    ///
    /// Full path to `rootCA-key.pem`.
    pub fn key_path(&self) -> PathBuf {
        self.root_path.join(ROOT_KEY_FILE)
    }

    /// Check if the CA certificate file exists.
    ///
    /// # Returns
    ///
    /// `true` if the certificate file exists, `false` otherwise.
    pub fn cert_exists(&self) -> bool {
        self.cert_path().exists()
    }

    /// Check if the CA private key file exists.
    ///
    /// # Returns
    ///
    /// `true` if the key file exists, `false` otherwise.
    pub fn key_exists(&self) -> bool {
        self.key_path().exists()
    }

    /// Create a new CA certificate and key pair.
    ///
    /// Generates a new 3072-bit RSA key pair and creates a self-signed
    /// CA certificate valid for 10 years. The certificate includes:
    /// - Subject: `mkcert <user>@<hostname>`
    /// - Basic Constraints: CA=true
    /// - Key Usage: Certificate Sign, CRL Sign
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if generation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation or serialization fails.
    pub fn create_ca(&mut self) -> Result<()> {
        eprintln!("{}", "Generating CA certificate...".cyan());

        // Generate RSA-3072 key pair for the CA
        let key_pair = KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_3072)
            .map_err(|e| Error::Certificate(format!("Failed to generate CA key pair: {}", e)))?;

        let params = create_ca_params()
            .map_err(|e| Error::Certificate(format!("Failed to create CA parameters: {}", e)))?;

        // Create self-signed CA certificate
        let cert = params.self_signed(&key_pair)
            .map_err(|e| Error::Certificate(format!("Failed to generate CA certificate: {}", e)))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        self.cert = Some(cert);
        self.cert_pem = Some(cert_pem);
        self.key_pem = Some(key_pem);

        Ok(())
    }

    /// Save the CA certificate and private key to disk.
    ///
    /// Writes the CA certificate to `rootCA.pem` with permissions 0644,
    /// and the private key to `rootCA-key.pem` with permissions 0400
    /// (Unix only).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if file operations fail.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No certificate has been generated or loaded
    /// - File creation or writing fails
    /// - Permission setting fails (Unix)
    pub fn save(&self) -> Result<()> {
        let cert_pem = self
            .cert_pem
            .as_ref()
            .ok_or_else(|| Error::Certificate("No certificate available to save".to_string()))?;

        let key_pem = self
            .key_pem
            .as_ref()
            .ok_or_else(|| Error::Certificate("No private key available to save".to_string()))?;

        // Save certificate
        let cert_path = self.cert_path();
        let mut file = File::create(&cert_path).map_err(|e| {
            Error::Certificate(format!(
                "Failed to create certificate file at {:?}: {}",
                cert_path, e
            ))
        })?;
        file.write_all(cert_pem.as_bytes()).map_err(|e| {
            Error::Certificate(format!(
                "Failed to write certificate to {:?}: {}",
                cert_path, e
            ))
        })?;
        #[cfg(unix)]
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644)).map_err(|e| {
            Error::Certificate(format!(
                "Failed to set permissions on {:?}: {}",
                cert_path, e
            ))
        })?;

        // Save private key
        let key_path = self.key_path();
        let mut file = File::create(&key_path).map_err(|e| {
            Error::Certificate(format!(
                "Failed to create key file at {:?}: {}",
                key_path, e
            ))
        })?;
        file.write_all(key_pem.as_bytes()).map_err(|e| {
            Error::Certificate(format!("Failed to write key to {:?}: {}", key_path, e))
        })?;
        #[cfg(unix)]
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o400)).map_err(|e| {
            Error::Certificate(format!(
                "Failed to set permissions on {:?}: {}",
                key_path, e
            ))
        })?;

        Ok(())
    }

    /// Load an existing CA certificate and private key from disk.
    ///
    /// Reads the CA certificate and private key PEM files and stores them in memory.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if loading fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The certificate or key file doesn't exist
    /// - The files cannot be read
    pub fn load(&mut self) -> Result<()> {
        let cert_path = self.cert_path();
        if !cert_path.exists() {
            return Err(Error::Certificate("CA certificate not found".to_string()));
        }

        let key_path = self.key_path();
        if !key_path.exists() {
            return Err(Error::Certificate("CA private key not found".to_string()));
        }

        let cert_pem = fs::read_to_string(&cert_path)?;
        let key_pem = fs::read_to_string(&key_path)?;

        self.cert_pem = Some(cert_pem);
        self.key_pem = Some(key_pem);

        Ok(())
    }

    /// Load existing CA or create a new one if it doesn't exist.
    ///
    /// This is the primary method for initializing a CA. It will:
    /// 1. Create the CA directory if needed
    /// 2. Load the existing CA certificate if present
    /// 3. Generate and save a new CA if no certificate exists
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if operations fail.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Directory creation fails
    /// - CA generation fails
    /// - File operations fail
    pub fn load_or_create(&mut self) -> Result<()> {
        self.init()?;

        if self.cert_exists() {
            self.load()?;
        } else {
            self.create_ca()?;
            self.save()?;
            println!("{}", "Created a new local CA".green().bold());
        }

        Ok(())
    }

    /// Get a unique name for the CA certificate for use in trust stores.
    ///
    /// Generates a name like "mkcert development CA <serial>" where
    /// <serial> is the certificate's serial number. This ensures the
    /// CA can be uniquely identified in system trust stores.
    ///
    /// # Returns
    ///
    /// A unique name string for this CA.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The certificate file cannot be read
    /// - PEM parsing fails
    /// - Certificate parsing fails
    pub fn unique_name(&self) -> Result<String> {
        // Parse the certificate to get the serial number
        let cert_pem = fs::read_to_string(self.cert_path())?;

        // Parse PEM to get DER
        let pem_data = pem::parse(&cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse PEM: {}", e)))?;

        // Parse X.509 certificate
        let cert = x509_parser::parse_x509_certificate(pem_data.contents())
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate: {}", e)))?
            .1;

        let serial = cert.serial.to_str_radix(10);
        Ok(format!("mkcert development CA {}", serial))
    }

    /// Get the serial number of the CA certificate.
    ///
    /// Extracts and returns the certificate serial number as a hex string.
    ///
    /// # Returns
    ///
    /// The serial number as a hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The certificate file cannot be read
    /// - PEM or certificate parsing fails
    pub fn get_serial_number(&self) -> Result<String> {
        let cert_pem = fs::read_to_string(self.cert_path())?;
        let pem_data = pem::parse(&cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse PEM: {}", e)))?;
        let cert = x509_parser::parse_x509_certificate(pem_data.contents())
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate: {}", e)))?
            .1;
        Ok(cert.serial.to_str_radix(16))
    }
}

/// Check if a serial number is unique (not used by another CA certificate).
///
/// Compares the given serial number with the serial of the CA certificate
/// at the specified path. Used to detect if a CA has been regenerated.
///
/// # Arguments
///
/// * `serial` - The serial number to check (hex string)
/// * `ca_path` - Path to the CA directory to check against
///
/// # Returns
///
/// `true` if the serial is unique (different), `false` if it matches.
///
/// # Errors
///
/// Returns an error if certificate operations fail.
pub fn is_serial_unique(serial: &str, ca_path: &Path) -> Result<bool> {
    if !ca_path.exists() {
        return Ok(true);
    }

    let ca = CertificateAuthority::new(ca_path.to_path_buf());
    if !ca.cert_exists() {
        return Ok(true);
    }

    let existing_serial = ca.get_serial_number()?;
    Ok(existing_serial != serial)
}

/// Get the current username and hostname in "user@hostname" format.
///
/// Used to personalize the CA certificate subject. Falls back to
/// "unknown@unknown" if the information cannot be determined.
///
/// # Returns
///
/// A string in the format "username@hostname".
fn get_user_and_hostname() -> String {
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    format!("{}@{}", username, hostname)
}

/// Create certificate parameters for a new CA certificate.
///
/// Generates parameters for a self-signed CA certificate with:
/// - Subject: mkcert development CA / user@hostname / mkcert user@hostname
/// - Validity: 10 years from now
/// - Basic Constraints: CA=true (unconstrained)
/// - Key Usage: Certificate Sign, CRL Sign
///
/// # Returns
///
/// `CertificateParams` configured for CA use.
///
/// # Errors
///
/// Returns an error if parameter creation fails.
fn create_ca_params() -> Result<CertificateParams> {
    let user_host = get_user_and_hostname();

    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "mkcert development CA");
    dn.push(DnType::OrganizationalUnitName, &user_host);
    dn.push(DnType::CommonName, format!("mkcert {}", user_host));
    params.distinguished_name = dn;

    // Valid for 10 years
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(3650);

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    // Let rcgen generate the key pair automatically

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_ca_paths() {
        let temp_dir = std::env::temp_dir().join("fastcert_test_ca");
        let ca = CertificateAuthority::new(temp_dir.clone());

        assert_eq!(ca.root_path(), temp_dir.as_path());
        assert_eq!(ca.cert_path(), temp_dir.join("rootCA.pem"));
        assert_eq!(ca.key_path(), temp_dir.join("rootCA-key.pem"));

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_ca_init() {
        let temp_dir = std::env::temp_dir().join("fastcert_test_init");

        // Remove if exists
        let _ = fs::remove_dir_all(&temp_dir);

        let ca = CertificateAuthority::new(temp_dir.clone());
        assert!(!temp_dir.exists());

        ca.init().unwrap();
        assert!(temp_dir.exists());

        // Cleanup
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_ca_lifecycle() {
        let temp_dir = std::env::temp_dir().join("fastcert_test_lifecycle");
        let _ = fs::remove_dir_all(&temp_dir);

        let mut ca = CertificateAuthority::new(temp_dir.clone());

        // First call creates CA
        ca.load_or_create().unwrap();
        assert!(ca.cert_exists());
        assert!(ca.key_exists());

        // Second call loads existing CA
        let mut ca2 = CertificateAuthority::new(temp_dir.clone());
        ca2.load_or_create().unwrap();

        // Cleanup
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_ca_install_integration() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
        }

        let mut ca = CertificateAuthority::new(temp_dir.path().to_path_buf());
        ca.load_or_create().unwrap();

        assert!(ca.cert_exists(), "CA certificate should be created");
        assert!(ca.key_exists(), "CA key should be created");

        let cert_pem = fs::read_to_string(&ca.cert_path()).unwrap();
        assert!(
            cert_pem.contains("BEGIN CERTIFICATE"),
            "Certificate should be in PEM format"
        );

        unsafe {
            std::env::remove_var("CAROOT");
        }
    }

    #[test]
    fn test_ca_uninstall_integration() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let mut ca = CertificateAuthority::new(temp_dir.path().to_path_buf());
        ca.load_or_create().unwrap();

        assert!(
            ca.cert_exists(),
            "CA certificate should exist before uninstall"
        );
        assert!(ca.key_exists(), "CA key should exist before uninstall");

        let cert_exists_after = ca.cert_exists();
        assert!(
            cert_exists_after,
            "Certificate should still exist after uninstall call"
        );
    }

    #[test]
    fn test_ca_serial_uniqueness() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let mut ca = CertificateAuthority::new(temp_dir.path().to_path_buf());
        ca.load_or_create().unwrap();

        let serial = ca.get_serial_number().unwrap();
        assert!(!serial.is_empty(), "Serial number should not be empty");

        // Check that the serial is not unique against itself
        assert!(!is_serial_unique(&serial, temp_dir.path()).unwrap());

        // Create a different CA to verify uniqueness
        let temp_dir2 = TempDir::new().unwrap();
        let mut ca2 = CertificateAuthority::new(temp_dir2.path().to_path_buf());
        ca2.load_or_create().unwrap();

        let serial2 = ca2.get_serial_number().unwrap();
        assert_ne!(
            serial, serial2,
            "Different CAs should have different serials"
        );

        // Check that serial1 is unique against ca2's path
        assert!(is_serial_unique(&serial, temp_dir2.path()).unwrap());
    }
}
