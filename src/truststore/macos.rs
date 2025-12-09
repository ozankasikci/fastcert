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

    /// Run a security command, optionally with sudo
    fn run_security_command(&self, args: &[&str], with_sudo: bool) -> Result<std::process::Output> {
        let output = if with_sudo {
            Command::new("sudo")
                .arg("security")
                .args(args)
                .output()
        } else {
            Command::new("security")
                .args(args)
                .output()
        };

        output.map_err(|e| Error::TrustStore(format!("Failed to run security command: {}", e)))
    }

    /// Check if the CA certificate is already installed in the system keychain
    fn is_installed(&self) -> Result<bool> {
        let output = self.run_security_command(
            &["find-certificate", "-a", "-c", "rscert", "/Library/Keychains/System.keychain"],
            false,
        )?;

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
