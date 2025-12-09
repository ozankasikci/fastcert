//! NSS/Firefox trust store

use crate::{Error, Result};
use super::TrustStore;
use std::path::{Path, PathBuf};
use std::env;

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
            globs.push(format!("{}/Library/Application Support/Firefox/Profiles/*", home.display()));
        }
        globs
    }

    #[cfg(target_os = "linux")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();
        if let Some(home) = dirs::home_dir() {
            globs.push(format!("{}/.mozilla/firefox/*", home.display()));
            globs.push(format!("{}/snap/firefox/common/.mozilla/firefox/*", home.display()));
        }
        globs
    }

    #[cfg(target_os = "windows")]
    fn get_firefox_profile_globs() -> Vec<String> {
        let mut globs = Vec::new();
        if let Ok(profile) = env::var("USERPROFILE") {
            globs.push(format!("{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*", profile));
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
}

impl TrustStore for NssTrustStore {
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
