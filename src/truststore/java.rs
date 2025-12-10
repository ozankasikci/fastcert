//! Java keystore

use super::TrustStore;
use crate::{Error, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct JavaTrustStore {
    cert_path: PathBuf,
    unique_name: String,
}

impl JavaTrustStore {
    pub fn new(cert_path: &Path, unique_name: String) -> Self {
        Self {
            cert_path: cert_path.to_path_buf(),
            unique_name,
        }
    }

    /// Detect JAVA_HOME and related paths
    fn detect_java() -> Option<JavaConfig> {
        let java_home = env::var("JAVA_HOME").ok()?;
        let java_home_path = PathBuf::from(&java_home);

        if !java_home_path.exists() {
            return None;
        }

        // Determine keytool path
        #[cfg(target_os = "windows")]
        let keytool_name = "keytool.exe";
        #[cfg(not(target_os = "windows"))]
        let keytool_name = "keytool";

        let keytool_path = java_home_path.join("bin").join(keytool_name);
        if !keytool_path.exists() {
            return None;
        }

        // Determine cacerts path
        // Try modern Java location first (lib/security/cacerts)
        let mut cacerts_path = java_home_path.join("lib/security/cacerts");
        if !cacerts_path.exists() {
            // Try older Java location (jre/lib/security/cacerts)
            cacerts_path = java_home_path.join("jre/lib/security/cacerts");
            if !cacerts_path.exists() {
                return None;
            }
        }

        Some(JavaConfig {
            java_home: java_home_path,
            keytool_path,
            cacerts_path,
        })
    }

    /// Check if Java is available
    pub fn is_available() -> bool {
        Self::detect_java().is_some()
    }

    /// Check if keytool is available
    pub fn has_keytool() -> bool {
        Self::detect_java()
            .map(|cfg| cfg.keytool_path.exists())
            .unwrap_or(false)
    }

    /// Execute keytool command
    /// If the command fails with FileNotFoundException on Unix, retry with sudo
    fn exec_keytool(args: &[&str]) -> Result<std::process::Output> {
        let config = Self::detect_java()
            .ok_or_else(|| Error::TrustStore("Java not found. Please set JAVA_HOME".to_string()))?;

        let output = Command::new(&config.keytool_path)
            .args(args)
            .output()
            .map_err(|e| Error::CommandFailed(format!("Failed to execute keytool: {}", e)))?;

        // Check if we need to retry with sudo (FileNotFoundException on Unix)
        #[cfg(unix)]
        {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("java.io.FileNotFoundException") {
                    // Retry with sudo and set JAVA_HOME environment variable
                    let output = Command::new("sudo")
                        .arg(&config.keytool_path)
                        .args(args)
                        .env("JAVA_HOME", &config.java_home)
                        .output()
                        .map_err(|e| {
                            Error::CommandFailed(format!(
                                "Failed to execute keytool with sudo: {}",
                                e
                            ))
                        })?;
                    return Ok(output);
                }
            }
        }

        Ok(output)
    }
}

#[derive(Debug)]
struct JavaConfig {
    java_home: PathBuf,
    keytool_path: PathBuf,
    cacerts_path: PathBuf,
}

impl TrustStore for JavaTrustStore {
    fn check(&self) -> Result<bool> {
        if !Self::has_keytool() {
            return Ok(false);
        }

        let config =
            Self::detect_java().ok_or_else(|| Error::TrustStore("Java not found".to_string()))?;

        let cacerts_str = config
            .cacerts_path
            .to_str()
            .ok_or_else(|| Error::TrustStore("Invalid cacerts path".to_string()))?;

        // Get the keytool list output
        let args = vec!["-list", "-keystore", cacerts_str, "-storepass", "changeit"];

        let output = Self::exec_keytool(&args)?;
        if !output.status.success() {
            return Ok(false);
        }

        // Read certificate and compute fingerprints
        let cert_pem = fs::read_to_string(&self.cert_path)?;
        let pem_data = pem::parse(&cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse PEM: {}", e)))?;

        let cert_der = pem_data.contents();

        // Compute SHA1 fingerprint
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(cert_der);
        let sha1_result = sha1_hasher.finalize();
        let sha1_hex = hex::encode_upper(sha1_result);

        // Compute SHA256 fingerprint
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(cert_der);
        let sha256_result = sha256_hasher.finalize();
        let sha256_hex = hex::encode_upper(sha256_result);

        // keytool outputs fingerprints with colons, we need to remove them for comparison
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stdout_no_colons = stdout.replace(":", "");

        // Check if either SHA1 or SHA256 fingerprint is present
        Ok(stdout_no_colons.contains(&sha1_hex) || stdout_no_colons.contains(&sha256_hex))
    }

    fn install(&self) -> Result<()> {
        if !Self::has_keytool() {
            return Err(Error::TrustStore(
                "keytool not found. Please set JAVA_HOME".to_string(),
            ));
        }

        let config =
            Self::detect_java().ok_or_else(|| Error::TrustStore("Java not found".to_string()))?;

        let cacerts_str = config
            .cacerts_path
            .to_str()
            .ok_or_else(|| Error::TrustStore("Invalid cacerts path".to_string()))?;

        let cert_path_str = self
            .cert_path
            .to_str()
            .ok_or_else(|| Error::TrustStore("Invalid certificate path".to_string()))?;

        let args = vec![
            "-importcert",
            "-noprompt",
            "-keystore",
            cacerts_str,
            "-storepass",
            "changeit",
            "-file",
            cert_path_str,
            "-alias",
            &self.unique_name,
        ];

        let output = Self::exec_keytool(&args)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::TrustStore(format!(
                "Failed to install certificate in Java keystore: {}",
                stderr
            )));
        }

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        if !Self::has_keytool() {
            // If keytool is not available, we can't uninstall but this is not an error
            return Ok(());
        }

        let config = match Self::detect_java() {
            Some(cfg) => cfg,
            None => return Ok(()),
        };

        let cacerts_str = match config.cacerts_path.to_str() {
            Some(s) => s,
            None => return Ok(()),
        };

        let args = vec![
            "-delete",
            "-alias",
            &self.unique_name,
            "-keystore",
            cacerts_str,
            "-storepass",
            "changeit",
        ];

        let output = Self::exec_keytool(&args)?;

        // Check if certificate doesn't exist (not an error)
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("does not exist") {
            return Ok(());
        }

        if !output.status.success() {
            // Log but don't fail on uninstall errors
            eprintln!(
                "Warning: Failed to remove certificate from Java keystore: {}",
                stderr
            );
        }

        Ok(())
    }
}
