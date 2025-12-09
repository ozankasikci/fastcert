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
        let store = macos::MacOSTrustStore::new(cert_path);
        store.install()?;
    }

    let ca = crate::ca::get_ca()?;
    let unique_name = ca.unique_name()?;

    // Also install to NSS/Firefox if available and enabled
    if is_store_enabled("nss") && nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox: {}", e);
        } else {
            println!("The local CA is now installed in Firefox trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java") && java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
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
        let store = linux::LinuxTrustStore::new(cert_path);
        store.install()?;
    }

    let ca = crate::ca::get_ca()?;
    let unique_name = ca.unique_name()?;

    // Also install to NSS/Firefox if available and enabled
    if is_store_enabled("nss") && nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox/Chromium: {}", e);
        } else {
            println!("The local CA is now installed in the Firefox and/or Chrome/Chromium trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java") && java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
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
        let store = windows::WindowsTrustStore::new(cert_path);
        store.install()?;
    }

    let ca = crate::ca::get_ca()?;
    let unique_name = ca.unique_name()?;

    // Also install to NSS/Firefox if available and enabled
    if is_store_enabled("nss") && nss::NssTrustStore::is_available() && nss::NssTrustStore::has_certutil() {
        let nss_store = nss::NssTrustStore::new(cert_path, unique_name.clone());
        if let Err(e) = nss_store.install() {
            eprintln!("Warning: Failed to install certificate in Firefox: {}", e);
        } else {
            println!("The local CA is now installed in Firefox trust store!");
        }
    }

    // Also install to Java keystore if available and enabled
    if is_store_enabled("java") && java::JavaTrustStore::is_available() && java::JavaTrustStore::has_keytool() {
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
