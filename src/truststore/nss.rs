//! NSS/Firefox trust store

use super::TrustStore;
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct NssTrustStore {
    cert_path: PathBuf,
    unique_name: String,
}

impl NssTrustStore {
    pub fn new(cert_path: &Path, unique_name: String) -> Self {
        Self {
            cert_path: cert_path.to_path_buf(),
            unique_name,
        }
    }

    /// Get NSS database directories (user home and system-wide)
    fn get_nss_dbs() -> Vec<PathBuf> {
        let mut dbs = Vec::new();

        if let Some(home) = dirs::home_dir() {
            // Standard NSS database location
            dbs.push(home.join(".pki/nssdb"));

            // Snapcraft Chromium
            dbs.push(home.join("snap/chromium/current/.pki/nssdb"));
        }

        // CentOS 7 system-wide
        dbs.push(PathBuf::from("/etc/pki/nssdb"));

        dbs
    }

    /// Get Firefox profile paths based on platform
    #[cfg(target_os = "macos")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();
        if let Some(home) = dirs::home_dir() {
            globs.push(format!(
                "{}/Library/Application Support/Firefox/Profiles/*",
                home.display()
            ));
        }
        globs
    }

    #[cfg(target_os = "linux")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();
        if let Some(home) = dirs::home_dir() {
            globs.push(format!("{}/.mozilla/firefox/*", home.display()));
            globs.push(format!(
                "{}/snap/firefox/common/.mozilla/firefox/*",
                home.display()
            ));
        }
        globs
    }

    #[cfg(target_os = "windows")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();
        if let Ok(profile) = std::env::var("USERPROFILE") {
            globs.push(format!(
                "{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*",
                profile
            ));
        }
        globs
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    fn get_firefox_profile_globs() -> Vec<String> {
        Vec::new()
    }

    /// Check if Firefox is installed
    fn has_firefox() -> bool {
        let firefox_paths = vec![
            "/usr/bin/firefox",
            "/usr/bin/firefox-nightly",
            "/usr/bin/firefox-developer-edition",
            "/snap/firefox",
            "/Applications/Firefox.app",
            "/Applications/FirefoxDeveloperEdition.app",
            "/Applications/Firefox Developer Edition.app",
            "/Applications/Firefox Nightly.app",
            "C:\\Program Files\\Mozilla Firefox",
        ];

        for path in firefox_paths {
            if Path::new(path).exists() {
                return true;
            }
        }

        false
    }

    /// Check if NSS is available
    pub fn is_available() -> bool {
        // Check if Firefox or NSS databases exist
        if Self::has_firefox() {
            return true;
        }

        for db in Self::get_nss_dbs() {
            if db.exists() {
                return true;
            }
        }

        false
    }

    /// Find all NSS profile directories with databases
    fn find_nss_profiles() -> Vec<(String, PathBuf)> {
        let mut profiles = Vec::new();

        // Add NSS databases
        for db in Self::get_nss_dbs() {
            if db.exists() && db.is_dir() {
                if db.join("cert9.db").exists() {
                    profiles.push(("sql".to_string(), db.clone()));
                } else if db.join("cert8.db").exists() {
                    profiles.push(("dbm".to_string(), db.clone()));
                }
            }
        }

        // Add Firefox profiles
        for pattern in Self::get_firefox_profile_globs() {
            if let Ok(paths) = glob::glob(&pattern) {
                for entry in paths.flatten() {
                    if entry.is_dir() {
                        if entry.join("cert9.db").exists() {
                            profiles.push(("sql".to_string(), entry.clone()));
                        } else if entry.join("cert8.db").exists() {
                            profiles.push(("dbm".to_string(), entry.clone()));
                        }
                    }
                }
            }
        }

        profiles
    }

    /// Find the certutil binary path
    fn find_certutil() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            // Check if certutil is in PATH
            if let Ok(output) = Command::new("which").arg("certutil").output()
                && output.status.success()
            {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }

            // Check default Homebrew path
            let homebrew_path = PathBuf::from("/usr/local/opt/nss/bin/certutil");
            if homebrew_path.exists() {
                return Some(homebrew_path);
            }

            // Try brew --prefix nss
            if let Ok(output) = Command::new("brew").args(["--prefix", "nss"]).output()
                && output.status.success()
            {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let certutil_path = PathBuf::from(prefix).join("bin/certutil");
                if certutil_path.exists() {
                    return Some(certutil_path);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check if certutil is in PATH
            if let Ok(output) = Command::new("which").arg("certutil").output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, check if certutil is in PATH
            if let Ok(output) = Command::new("where").arg("certutil").output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }

        None
    }

    /// Check if certutil is available
    pub fn has_certutil() -> bool {
        Self::find_certutil().is_some()
    }

    /// Execute certutil command
    /// If the command fails with SEC_ERROR_READ_ONLY on Unix, retry with sudo
    fn exec_certutil(args: &[&str]) -> Result<std::process::Output> {
        let certutil_path = Self::find_certutil()
            .ok_or_else(|| Error::TrustStore("certutil not found".to_string()))?;

        let output = Command::new(&certutil_path)
            .args(args)
            .output()
            .map_err(|e| Error::CommandFailed(format!("Failed to execute certutil: {}", e)))?;

        // Check if we need to retry with sudo (SEC_ERROR_READ_ONLY on Unix)
        #[cfg(unix)]
        {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("SEC_ERROR_READ_ONLY") {
                    // Retry with sudo
                    let output = Command::new("sudo")
                        .arg(&certutil_path)
                        .args(args)
                        .output()
                        .map_err(|e| {
                            Error::CommandFailed(format!(
                                "Failed to execute certutil with sudo: {}",
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

impl TrustStore for NssTrustStore {
    fn check(&self) -> Result<bool> {
        if !Self::has_certutil() {
            return Ok(false);
        }

        let profiles = Self::find_nss_profiles();
        if profiles.is_empty() {
            return Ok(false);
        }

        let mut success = true;
        for (db_type, profile_path) in profiles {
            let db_arg = format!("{}:{}", db_type, profile_path.display());

            let args = vec!["-V", "-d", &db_arg, "-u", "L", "-n", &self.unique_name];

            match Self::exec_certutil(&args) {
                Ok(output) => {
                    if !output.status.success() {
                        success = false;
                    }
                }
                Err(_) => {
                    success = false;
                }
            }
        }

        Ok(success)
    }

    fn install(&self) -> Result<()> {
        if !Self::has_certutil() {
            return Err(Error::TrustStore(
                "certutil not found. Please install NSS tools.".to_string(),
            ));
        }

        let profiles = Self::find_nss_profiles();
        if profiles.is_empty() {
            return Err(Error::TrustStore(
                "No NSS security databases found. Please start Firefox at least once.".to_string(),
            ));
        }

        let cert_path_str = self
            .cert_path
            .to_str()
            .ok_or_else(|| Error::TrustStore("Invalid certificate path".to_string()))?;

        for (db_type, profile_path) in &profiles {
            let db_arg = format!("{}:{}", db_type, profile_path.display());

            let args = vec![
                "-A",
                "-d",
                &db_arg,
                "-t",
                "C,,",
                "-n",
                &self.unique_name,
                "-i",
                cert_path_str,
            ];

            let output = Self::exec_certutil(&args)?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::TrustStore(format!(
                    "Failed to install certificate in NSS database {}: {}",
                    profile_path.display(),
                    stderr
                )));
            }
        }

        // Verify installation
        if !self.check()? {
            return Err(Error::TrustStore(
                "Certificate installation verification failed. Please report this issue."
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        if !Self::has_certutil() {
            // If certutil is not available, we can't uninstall but this is not an error
            return Ok(());
        }

        let profiles = Self::find_nss_profiles();
        if profiles.is_empty() {
            // No profiles found, nothing to uninstall
            return Ok(());
        }

        for (db_type, profile_path) in &profiles {
            let db_arg = format!("{}:{}", db_type, profile_path.display());

            // First check if the certificate exists in this profile
            let check_args = vec!["-V", "-d", &db_arg, "-u", "L", "-n", &self.unique_name];

            match Self::exec_certutil(&check_args) {
                Ok(output) => {
                    if !output.status.success() {
                        // Certificate doesn't exist in this profile, skip
                        continue;
                    }
                }
                Err(_) => {
                    // Error checking, skip this profile
                    continue;
                }
            }

            // Certificate exists, delete it
            let delete_args = vec!["-D", "-d", &db_arg, "-n", &self.unique_name];

            let output = Self::exec_certutil(&delete_args)?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Log but don't fail on uninstall errors
                eprintln!(
                    "Warning: Failed to remove certificate from NSS database {}: {}",
                    profile_path.display(),
                    stderr
                );
            }
        }

        Ok(())
    }
}
