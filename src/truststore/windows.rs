//! Windows trust store

use crate::{Error, Result};
use super::TrustStore;
use std::path::Path;

#[cfg(target_os = "windows")]
use {
    std::ptr,
    windows::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
        CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertOpenSystemStoreW,
        CERT_CONTEXT, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
        HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    },
    windows::core::PCWSTR,
};

pub struct WindowsTrustStore {
    cert_path: String,
}

impl WindowsTrustStore {
    pub fn new(cert_path: &Path) -> Self {
        Self {
            cert_path: cert_path.to_string_lossy().to_string(),
        }
    }

    #[cfg(target_os = "windows")]
    fn open_root_store(&self) -> Result<WindowsRootStore> {
        WindowsRootStore::open()
    }

    #[cfg(not(target_os = "windows"))]
    fn open_root_store(&self) -> Result<WindowsRootStore> {
        Err(Error::TrustStore("Windows trust store is only available on Windows".to_string()))
    }
}

#[cfg(target_os = "windows")]
struct WindowsRootStore {
    handle: HCERTSTORE,
}

#[cfg(target_os = "windows")]
impl WindowsRootStore {
    fn open() -> Result<Self> {
        unsafe {
            let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
            let handle = CertOpenSystemStoreW(
                None,
                PCWSTR(store_name.as_ptr()),
            )?;

            if handle.is_invalid() {
                return Err(Error::TrustStore("Failed to open Windows root store".to_string()));
            }

            Ok(Self { handle })
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsRootStore {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(self.handle, 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
struct WindowsRootStore;

impl TrustStore for WindowsTrustStore {
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
