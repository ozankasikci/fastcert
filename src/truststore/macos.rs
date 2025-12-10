//! macOS Keychain trust store

use super::TrustStore;
use crate::{Error, Result};
use std::path::Path;
use std::process::Command;

// Trust settings plist data for SSL and basicX509 policies
// This ensures the certificate is trusted for SSL server authentication
const TRUST_SETTINGS_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAED
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>sslServer</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAEC
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>basicX509</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
</array>
</plist>
"#;

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
            Command::new("sudo").arg("security").args(args).output()
        } else {
            Command::new("security").args(args).output()
        };

        output.map_err(|e| Error::TrustStore(format!("Failed to run security command: {}", e)))
    }

    /// Check if the CA certificate is already installed in the system keychain
    fn is_installed(&self) -> Result<bool> {
        let output = self.run_security_command(
            &[
                "find-certificate",
                "-a",
                "-c",
                "rscert",
                "/Library/Keychains/System.keychain",
            ],
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
        // Check if already installed
        if self.is_installed()? {
            println!("The local CA certificate is already installed in the macOS keychain.");
            return Ok(());
        }

        println!("Installing CA certificate to macOS keychain...");
        println!("Note: This will require administrator privileges.");

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
            if stderr.contains("User interaction is not allowed") {
                return Err(Error::TrustStore(
                    "Failed to add certificate: User cancelled the operation or authorization failed".to_string()
                ));
            } else if stderr.contains("The authorization was denied") {
                return Err(Error::TrustStore(
                    "Failed to add certificate: Administrator authorization was denied".to_string(),
                ));
            }
            return Err(Error::TrustStore(format!(
                "Failed to add certificate to keychain: {}",
                stderr
            )));
        }

        println!("The local CA certificate is now installed in the macOS keychain.");
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        // Check if not installed
        if !self.is_installed()? {
            println!("The local CA certificate is not installed in the macOS keychain.");
            return Ok(());
        }

        println!("Removing CA certificate from macOS keychain...");
        println!("Note: This will require administrator privileges.");

        // Remove the certificate from the system keychain
        let output =
            self.run_security_command(&["remove-trusted-cert", "-d", &self.cert_path], true)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("User interaction is not allowed") {
                return Err(Error::TrustStore(
                    "Failed to remove certificate: User cancelled the operation or authorization failed".to_string()
                ));
            } else if stderr.contains("The authorization was denied") {
                return Err(Error::TrustStore(
                    "Failed to remove certificate: Administrator authorization was denied"
                        .to_string(),
                ));
            } else if stderr.contains("The specified item could not be found") {
                println!("The local CA certificate was not found in the macOS keychain.");
                return Ok(());
            }
            return Err(Error::TrustStore(format!(
                "Failed to remove certificate from keychain: {}",
                stderr
            )));
        }

        println!("The local CA certificate has been removed from the macOS keychain.");
        Ok(())
    }
}
