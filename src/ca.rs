//! Certificate Authority management

use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::fs;
use rcgen::Certificate;

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
}
