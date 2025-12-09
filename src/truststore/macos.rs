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
        // Add the certificate as a trusted cert to the system keychain
        let output = self.run_security_command(
            &[
                "add-trusted-cert",
                "-d",
                "-k",
                "/Library/Keychains/System.keychain",
                &self.cert_path,
            ],
            true,
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::TrustStore(format!(
                "Failed to add certificate to keychain: {}",
                stderr
            )));
        }

        println!("The local CA certificate is now installed in the macOS keychain.");
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        // Remove the certificate from the system keychain
        let output = self.run_security_command(
            &[
                "remove-trusted-cert",
                "-d",
                &self.cert_path,
            ],
            true,
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::TrustStore(format!(
                "Failed to remove certificate from keychain: {}",
                stderr
            )));
        }

        println!("The local CA certificate has been removed from the macOS keychain.");
        Ok(())
    }
}
