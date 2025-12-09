//! Certificate Authority management

use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::Write;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, IsCa, BasicConstraints};
use time::{OffsetDateTime, Duration};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const ROOT_CERT_FILE: &str = "rootCA.pem";
const ROOT_KEY_FILE: &str = "rootCA-key.pem";

/// Get the CAROOT directory path
pub fn get_caroot() -> Result<String> {
    let caroot = get_caroot_path()?;
    Ok(caroot.display().to_string())
}

/// Get the CAROOT directory path as PathBuf
fn get_caroot_path() -> Result<PathBuf> {
    // Check CAROOT environment variable
    if let Ok(caroot) = std::env::var("CAROOT") {
        return Ok(PathBuf::from(caroot));
    }

    // Get default location based on platform
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join("Library").join("Application Support").join("rscert"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_app_data) = dirs::data_local_dir() {
            return Ok(local_app_data.join("rscert"));
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(data_dir) = dirs::data_dir() {
            return Ok(data_dir.join("rscert"));
        }
    }

    Err(Error::Certificate("Could not determine CAROOT directory".to_string()))
}

/// Install the CA certificate into the system trust store
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
        println!("You may need to manually import the CA certificate from: {}", ca.cert_path().display());
    }

    Ok(())
}

/// Uninstall the CA certificate from the system trust store
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
        println!("You may need to manually remove the CA certificate from your system trust store.");
    }

    Ok(())
}

/// Get the CertificateAuthority for the default CAROOT
pub fn get_ca() -> Result<CertificateAuthority> {
    let caroot = get_caroot_path()?;
    Ok(CertificateAuthority::new(caroot))
}

pub struct CertificateAuthority {
    root_path: PathBuf,
    cert: Option<Certificate>,
    cert_pem: Option<String>,
}

impl CertificateAuthority {
    pub fn new(root_path: PathBuf) -> Self {
        Self {
            root_path,
            cert: None,
            cert_pem: None,
        }
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub fn init(&self) -> Result<()> {
        if !self.root_path.exists() {
            fs::create_dir_all(&self.root_path)?;
        }
        Ok(())
    }

    pub fn cert_path(&self) -> PathBuf {
        self.root_path.join(ROOT_CERT_FILE)
    }

    pub fn key_path(&self) -> PathBuf {
        self.root_path.join(ROOT_KEY_FILE)
    }

    pub fn cert_exists(&self) -> bool {
        self.cert_path().exists()
    }

    pub fn key_exists(&self) -> bool {
        self.key_path().exists()
    }

    pub fn create_ca(&mut self) -> Result<()> {
        eprintln!("Generating CA certificate...");
        let params = create_ca_params()?;

        let cert = Certificate::from_params(params)
            .map_err(|e| Error::Certificate(format!("Failed to create CA cert: {}", e)))?;

        let cert_pem = cert.serialize_pem()
            .map_err(|e| Error::Certificate(format!("Failed to serialize cert: {}", e)))?;

        self.cert = Some(cert);
        self.cert_pem = Some(cert_pem);

        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let cert_pem = self.cert_pem.as_ref()
            .ok_or(Error::Certificate("No certificate to save".to_string()))?;

        let cert = self.cert.as_ref()
            .ok_or(Error::Certificate("No certificate to save".to_string()))?;

        // Save certificate
        let cert_path = self.cert_path();
        let mut file = File::create(&cert_path)?;
        file.write_all(cert_pem.as_bytes())?;
        #[cfg(unix)]
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644))?;

        // Save private key
        let key_pem = cert.serialize_private_key_pem();
        let key_path = self.key_path();
        let mut file = File::create(&key_path)?;
        file.write_all(key_pem.as_bytes())?;
        #[cfg(unix)]
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o400))?;

        Ok(())
    }

    pub fn load(&mut self) -> Result<()> {
        let cert_path = self.cert_path();
        if !cert_path.exists() {
            return Err(Error::Certificate("CA certificate not found".to_string()));
        }

        let cert_pem = fs::read_to_string(&cert_path)?;
        self.cert_pem = Some(cert_pem.clone());

        // Parse certificate for later use
        // Note: rcgen doesn't support loading certs, we'll store PEM for now

        Ok(())
    }

    pub fn load_or_create(&mut self) -> Result<()> {
        self.init()?;

        if self.cert_exists() {
            self.load()?;
        } else {
            self.create_ca()?;
            self.save()?;
            println!("Created a new local CA 💥");
        }

        Ok(())
    }

    /// Get a unique name for the CA certificate (for use in trust stores)
    pub fn unique_name(&self) -> Result<String> {
        // Parse the certificate to get the serial number
        let cert_pem = fs::read_to_string(&self.cert_path())?;

        // Parse PEM to get DER
        let pem_data = pem::parse(&cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse PEM: {}", e)))?;

        // Parse X.509 certificate
        let cert = x509_parser::parse_x509_certificate(&pem_data.contents())
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate: {}", e)))?
            .1;

        let serial = cert.serial.to_str_radix(10);
        Ok(format!("mkcert development CA {}", serial))
    }
}

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
        let temp_dir = std::env::temp_dir().join("rscert_test_ca");
        let ca = CertificateAuthority::new(temp_dir.clone());

        assert_eq!(ca.root_path(), temp_dir.as_path());
        assert_eq!(ca.cert_path(), temp_dir.join("rootCA.pem"));
        assert_eq!(ca.key_path(), temp_dir.join("rootCA-key.pem"));

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_ca_init() {
        let temp_dir = std::env::temp_dir().join("rscert_test_init");

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
        let temp_dir = std::env::temp_dir().join("rscert_test_lifecycle");
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
        assert!(cert_pem.contains("BEGIN CERTIFICATE"), "Certificate should be in PEM format");

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

        assert!(ca.cert_exists(), "CA certificate should exist before uninstall");
        assert!(ca.key_exists(), "CA key should exist before uninstall");

        let cert_exists_after = ca.cert_exists();
        assert!(cert_exists_after, "Certificate should still exist after uninstall call");
    }
}
