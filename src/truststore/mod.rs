//! Platform-specific trust store implementations.
//!
//! This module provides integration with system and application trust stores
//! across different platforms. It supports:
//! - System trust stores (macOS Keychain, Linux CA certificates, Windows Certificate Store)
//! - NSS-based browsers (Firefox, Chrome on Linux)
//! - Java KeyStore
//!
//! Trust store selection can be controlled via the `TRUST_STORES` environment
//! variable (comma-separated list of: system, nss, java).

use crate::Result;
use std::env;
use std::path::Path;

/// Parse TRUST_STORES environment variable to determine which stores to use.
///
/// If the environment variable is not set, all available stores are enabled
/// by default (system, nss, java).
///
/// # Returns
///
/// A vector of enabled store names (lowercase).
pub fn get_enabled_stores() -> Vec<String> {
    if let Ok(trust_stores) = env::var("TRUST_STORES") {
        trust_stores
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        // Default: all stores
        vec!["system".to_string(), "nss".to_string(), "java".to_string()]
    }
}

/// Check if a specific trust store is enabled via environment variable.
///
/// # Arguments
///
/// * `store` - The store name to check (case-insensitive)
///
/// # Returns
///
/// `true` if the store is enabled, `false` otherwise.
pub fn is_store_enabled(store: &str) -> bool {
    let enabled = get_enabled_stores();
    enabled.contains(&store.to_lowercase())
}

/// Enumerate all available trust stores on this system.
///
/// Checks for the presence of required tools (certutil, keytool) and
/// returns a list of trust stores that can be used.
///
/// # Returns
///
/// A vector of human-readable store descriptions.
pub fn enumerate_available_stores() -> Vec<String> {
    let mut stores = Vec::new();

    // Check for system store
    #[cfg(target_os = "macos")]
    stores.push("system (macOS Keychain)".to_string());

    #[cfg(target_os = "linux")]
    stores.push("system (Linux CA certificates)".to_string());

    #[cfg(target_os = "windows")]
    stores.push("system (Windows Certificate Store)".to_string());

    // Check for NSS/Firefox
    if nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
        stores.push("nss (Firefox/Chromium)".to_string());
    }

    // Check for Java
    if java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
        stores.push("java (Java Keystore)".to_string());
    }

    stores
}

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

pub mod java;
pub mod nss;

/// Common interface for trust store operations.
///
/// Implementations handle platform-specific certificate installation
/// and removal from trust stores.
pub trait TrustStore {
    /// Check if the certificate is installed in this trust store.
    fn check(&self) -> Result<bool>;

    /// Install the certificate to this trust store.
    fn install(&self) -> Result<()>;

    /// Remove the certificate from this trust store.
    fn uninstall(&self) -> Result<()>;
}

/// Install CA certificate to macOS trust stores.
///
/// Installs the certificate to the System Keychain and optionally to
/// Firefox NSS and Java KeyStore if available.
///
/// # Arguments
///
/// * `cert_path` - Path to the CA certificate file
///
/// # Returns
///
/// `Ok(())` on success, or an error if installation fails.
#[cfg(target_os = "macos")]
pub fn install_macos(cert_path: &Path) -> Result<()> {
    // Install to system store if enabled
    if is_store_enabled("system") {
        eprintln!("Installing to system trust store...");
        let store = macos::MacOSTrustStore::new(cert_path);
        store.install()?;
    }

    let ca = crate::ca::get_ca()?;
    let unique_name = ca.unique_name()?;

    // Also install to NSS/Firefox if available and enabled
    if is_store_enabled("nss")
        && nss::NssTrustStore::is_available()
        && nss::NssTrustStore::has_certutil()
    {
        eprintln!("Installing to Firefox/NSS trust store...");
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox: {}", e);
        } else {
            println!("The local CA is now installed in Firefox trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java")
        && java::JavaTrustStore::is_available()
        && java::JavaTrustStore::has_keytool()
    {
        eprintln!("Installing to Java trust store...");
        let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = java_store.install() {
            eprintln!(
                "Warning: Failed to install certificate in Java keystore: {}",
                e
            );
        } else {
            println!("The local CA is now installed in Java trust store!");
        }
    }

    Ok(())
}

/// Uninstall CA certificate from macOS trust stores.
///
/// Removes the certificate from the System Keychain and optionally from
/// Firefox NSS and Java KeyStore if they were previously installed.
///
/// # Arguments
///
/// * `cert_path` - Path to the CA certificate file
///
/// # Returns
///
/// `Ok(())` on success, or an error if uninstallation fails.
#[cfg(target_os = "macos")]
pub fn uninstall_macos(cert_path: &Path) -> Result<()> {
    let store = macos::MacOSTrustStore::new(cert_path);
    store.uninstall()?;

    // Also uninstall from NSS/Firefox and Java if available
    let ca = crate::ca::get_ca()?;
    if let Ok(unique_name) = ca.unique_name() {
        if nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
            let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = nss_store.uninstall() {
                eprintln!(
                    "Warning: Failed to uninstall certificate from Firefox: {}",
                    e
                );
            }
        }

        if java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
            let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = java_store.uninstall() {
                eprintln!(
                    "Warning: Failed to uninstall certificate from Java keystore: {}",
                    e
                );
            }
        }
    }

    Ok(())
}

/// Install CA certificate to Linux trust stores.
///
/// Installs the certificate to the system CA directory and optionally to
/// Firefox NSS and Java KeyStore if available.
///
/// # Arguments
///
/// * `cert_path` - Path to the CA certificate file
///
/// # Returns
///
/// `Ok(())` on success, or an error if installation fails.
#[cfg(target_os = "linux")]
pub fn install_linux(cert_path: &Path) -> Result<()> {
    // Install to system store if enabled
    if is_store_enabled("system") {
        eprintln!("Installing to system trust store...");
        let store = linux::LinuxTrustStore::new(cert_path);
        store.install()?;
    }

    let ca = crate::ca::get_ca()?;
    let unique_name = ca.unique_name()?;

    // Also install to NSS/Firefox if available and enabled
    if is_store_enabled("nss")
        && nss::NssTrustStore::is_available()
        && nss::NssTrustStore::has_certutil()
    {
        eprintln!("Installing to Firefox/Chromium trust store...");
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!(
                "Warning: Failed to install certificate in Firefox/Chromium: {}",
                e
            );
        } else {
            println!(
                "The local CA is now installed in the Firefox and/or Chrome/Chromium trust store!"
            );
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java")
        && java::JavaTrustStore::is_available()
        && java::JavaTrustStore::has_keytool()
    {
        eprintln!("Installing to Java trust store...");
        let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = java_store.install() {
            eprintln!(
                "Warning: Failed to install certificate in Java keystore: {}",
                e
            );
        } else {
            println!("The local CA is now installed in Java trust store!");
        }
    }

    Ok(())
}

/// Uninstall CA certificate from Linux trust stores.
///
/// Removes the certificate from the system CA directory and optionally from
/// Firefox NSS and Java KeyStore if they were previously installed.
///
/// # Arguments
///
/// * `cert_path` - Path to the CA certificate file
///
/// # Returns
///
/// `Ok(())` on success, or an error if uninstallation fails.
#[cfg(target_os = "linux")]
pub fn uninstall_linux(cert_path: &Path) -> Result<()> {
    let store = linux::LinuxTrustStore::new(cert_path);
    store.uninstall()?;

    // Also uninstall from NSS/Firefox and Java if available
    let ca = crate::ca::get_ca()?;
    if let Ok(unique_name) = ca.unique_name() {
        if nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
            let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = nss_store.uninstall() {
                eprintln!(
                    "Warning: Failed to uninstall certificate from Firefox/Chromium: {}",
                    e
                );
            }
        }

        if java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
            let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = java_store.uninstall() {
                eprintln!(
                    "Warning: Failed to uninstall certificate from Java keystore: {}",
                    e
                );
            }
        }
    }

    Ok(())
}

/// Install CA certificate to Windows trust stores.
///
/// Installs the certificate to the Windows Certificate Store and optionally
/// to Firefox NSS and Java KeyStore if available.
///
/// # Arguments
///
/// * `cert_path` - Path to the CA certificate file
///
/// # Returns
///
/// `Ok(())` on success, or an error if installation fails.
#[cfg(target_os = "windows")]
pub fn install_windows(cert_path: &Path) -> Result<()> {
    // Install to system store if enabled
    if is_store_enabled("system") {
        eprintln!("Installing to system trust store...");
        let store = windows::WindowsTrustStore::new(cert_path);
        store.install()?;
    }

    let ca = crate::ca::get_ca()?;
    let unique_name = ca.unique_name()?;

    // Also install to NSS/Firefox if available and enabled
    if is_store_enabled("nss")
        && nss::NssTrustStore::is_available()
        && nss::NssTrustStore::has_certutil()
    {
        eprintln!("Installing to Firefox trust store...");
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox: {}", e);
        } else {
            println!("The local CA is now installed in Firefox trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java")
        && java::JavaTrustStore::is_available()
        && java::JavaTrustStore::has_keytool()
    {
        eprintln!("Installing to Java trust store...");
        let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = java_store.install() {
            eprintln!(
                "Warning: Failed to install certificate in Java keystore: {}",
                e
            );
        } else {
            println!("The local CA is now installed in Java trust store!");
        }
    }

    Ok(())
}

/// Uninstall CA certificate from Windows trust stores.
///
/// Removes the certificate from the Windows Certificate Store and optionally
/// from Firefox NSS and Java KeyStore if they were previously installed.
///
/// # Arguments
///
/// * `cert_path` - Path to the CA certificate file
///
/// # Returns
///
/// `Ok(())` on success, or an error if uninstallation fails.
#[cfg(target_os = "windows")]
pub fn uninstall_windows(cert_path: &Path) -> Result<()> {
    let store = windows::WindowsTrustStore::new(cert_path);
    store.uninstall()?;

    // Also uninstall from NSS/Firefox and Java if available
    let ca = crate::ca::get_ca()?;
    if let Ok(unique_name) = ca.unique_name() {
        if nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
            let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = nss_store.uninstall() {
                eprintln!(
                    "Warning: Failed to uninstall certificate from Firefox: {}",
                    e
                );
            }
        }

        if java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
            let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = java_store.uninstall() {
                eprintln!(
                    "Warning: Failed to uninstall certificate from Java keystore: {}",
                    e
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_available_stores() {
        let stores = enumerate_available_stores();

        // Should have at least the system store
        assert!(!stores.is_empty(), "Should find at least one trust store");

        // Check that system store is present
        assert!(
            stores.iter().any(|s| s.contains("system")),
            "System store should be available"
        );
    }

    #[test]
    fn test_get_enabled_stores_default() {
        // Clear TRUST_STORES env var for this test
        unsafe {
            std::env::remove_var("TRUST_STORES");
        }

        let stores = get_enabled_stores();
        assert!(stores.contains(&"system".to_string()));
        assert!(stores.contains(&"nss".to_string()));
        assert!(stores.contains(&"java".to_string()));
    }

    #[test]
    fn test_is_store_enabled() {
        unsafe {
            std::env::remove_var("TRUST_STORES");
        }

        assert!(is_store_enabled("system"));
        assert!(is_store_enabled("nss"));
        assert!(is_store_enabled("java"));
    }
}
