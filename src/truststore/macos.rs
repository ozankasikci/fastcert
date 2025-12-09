//! macOS Keychain trust store

use crate::{Error, Result};
use super::TrustStore;
use std::path::Path;
use std::process::Command;

pub struct MacOSTrustStore {
    cert_path: String,
}

impl MacOSTrustStore {
    pub fn new(cert_path: &Path) -> Self {
        Self {
            cert_path: cert_path.to_string_lossy().to_string(),
        }
    }

    /// Check if the CA certificate is already installed in the system keychain
    fn is_installed(&self) -> Result<bool> {
        let output = Command::new("security")
            .args(&["find-certificate", "-a", "-c", "rscert"])
            .arg("/Library/Keychains/System.keychain")
            .output()
            .map_err(|e| Error::TrustStore(format!("Failed to run security command: {}", e)))?;

        // If the certificate is found, the command will output its details
        Ok(!output.stdout.is_empty())
    }
}

impl TrustStore for MacOSTrustStore {
    fn check(&self) -> Result<bool> {
        self.is_installed()
    }

    fn install(&self) -> Result<()> {
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        Ok(())
    }
}
