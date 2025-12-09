//! Platform-specific trust store implementations

use crate::Result;
use std::path::Path;

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
    let store = macos::MacOSTrustStore::new(cert_path);
    store.install()
}

#[cfg(target_os = "macos")]
pub fn uninstall_macos(cert_path: &Path) -> Result<()> {
    let store = macos::MacOSTrustStore::new(cert_path);
    store.uninstall()
}

#[cfg(target_os = "windows")]
pub fn install_windows(_cert_path: &Path) -> Result<()> {
    println!("Note: Windows trust store installation not yet implemented.");
    println!("Please manually import the CA certificate into the Windows Certificate Store.");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall_windows(_cert_path: &Path) -> Result<()> {
    println!("Note: Windows trust store uninstallation not yet implemented.");
    println!("Please manually remove the CA certificate from the Windows Certificate Store.");
    Ok(())
}
