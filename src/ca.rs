//! Certificate Authority management

use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::fs;
use rcgen::{Certificate, CertificateParams, KeyPair, PKCS_RSA_SHA256, DistinguishedName, DnType, IsCa, BasicConstraints};
use time::{OffsetDateTime, Duration};

const ROOT_CERT_FILE: &str = "rootCA.pem";
const ROOT_KEY_FILE: &str = "rootCA-key.pem";

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
        let keypair = generate_ca_keypair()?;
        let params = create_ca_params(keypair)?;

        let cert = Certificate::from_params(params)
            .map_err(|e| Error::Certificate(format!("Failed to create CA cert: {}", e)))?;

        let cert_pem = cert.serialize_pem()
            .map_err(|e| Error::Certificate(format!("Failed to serialize cert: {}", e)))?;

        self.cert = Some(cert);
        self.cert_pem = Some(cert_pem);

        Ok(())
    }
}

fn generate_ca_keypair() -> Result<KeyPair> {
    let keypair = KeyPair::generate(&PKCS_RSA_SHA256)
        .map_err(|e| Error::Certificate(format!("Failed to generate key: {}", e)))?;
    Ok(keypair)
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

fn create_ca_params(keypair: KeyPair) -> Result<CertificateParams> {
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

    params.key_pair = Some(keypair);

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
}
