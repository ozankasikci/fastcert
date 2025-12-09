//! Java keystore

use crate::{Error, Result};
use super::TrustStore;
use std::path::{Path, PathBuf};
use std::env;
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
                        .map_err(|e| Error::CommandFailed(format!("Failed to execute keytool with sudo: {}", e)))?;
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
        Ok(false)
    }

    fn install(&self) -> Result<()> {
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        Ok(())
    }
}
