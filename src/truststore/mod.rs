//! Platform-specific trust store implementations

use crate::Result;
use std::path::Path;
use std::env;

/// Parse TRUST_STORES environment variable to determine which stores to use
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

/// Check if a specific store is enabled
pub fn is_store_enabled(store: &str) -> bool {
    let enabled = get_enabled_stores();
    enabled.contains(&store.to_lowercase())
}

/// Enumerate all available trust stores on this system
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

pub mod nss;
pub mod java;

pub trait TrustStore {
    fn check(&self) -> Result<bool>;
    fn install(&self) -> Result<()>;
    fn uninstall(&self) -> Result<()>;
}

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
    if is_store_enabled("nss") && nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
        eprintln!("Installing to Firefox/NSS trust store...");
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox: {}", e);
        } else {
            println!("The local CA is now installed in Firefox trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java") && java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
        eprintln!("Installing to Java trust store...");
        let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = java_store.install() {
            eprintln!("Warning: Failed to install certificate in Java keystore: {}", e);
        } else {
            println!("The local CA is now installed in Java trust store!");
        }
    }

    Ok(())
}

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
                eprintln!("Warning: Failed to uninstall certificate from Firefox: {}", e);
            }
        }

        if java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
            let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = java_store.uninstall() {
                eprintln!("Warning: Failed to uninstall certificate from Java keystore: {}", e);
            }
        }
    }

    Ok(())
}

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
    if is_store_enabled("nss") && nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
        eprintln!("Installing to Firefox/Chromium trust store...");
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox/Chromium: {}", e);
        } else {
            println!("The local CA is now installed in the Firefox and/or Chrome/Chromium trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java") && java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
        eprintln!("Installing to Java trust store...");
        let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = java_store.install() {
            eprintln!("Warning: Failed to install certificate in Java keystore: {}", e);
        } else {
            println!("The local CA is now installed in Java trust store!");
        }
    }

    Ok(())
}

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
                eprintln!("Warning: Failed to uninstall certificate from Firefox/Chromium: {}", e);
            }
        }

        if java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
            let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = java_store.uninstall() {
                eprintln!("Warning: Failed to uninstall certificate from Java keystore: {}", e);
            }
        }
    }

    Ok(())
}

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
    if is_store_enabled("nss") && nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
        eprintln!("Installing to Firefox trust store...");
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox: {}", e);
        } else {
            println!("The local CA is now installed in Firefox trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java") && java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
        eprintln!("Installing to Java trust store...");
        let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = java_store.install() {
            eprintln!("Warning: Failed to install certificate in Java keystore: {}", e);
        } else {
            println!("The local CA is now installed in Java trust store!");
        }
    }

    Ok(())
}

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
                eprintln!("Warning: Failed to uninstall certificate from Firefox: {}", e);
            }
        }

        if java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
            let java_store = java::JavaTrustStore::new(cert_path, unique_name.clone());
            if let Err(e) = java_store.uninstall() {
                eprintln!("Warning: Failed to uninstall certificate from Java keystore: {}", e);
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
        assert!(stores.iter().any(|s| s.contains("system")), "System store should be available");
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
