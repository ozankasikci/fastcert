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

    fn load_cert_der(&self) -> Result<Vec<u8>> {
        let cert_pem = std::fs::read_to_string(&self.cert_path)
            .map_err(|e| Error::TrustStore(format!("Failed to read certificate: {}", e)))?;

        let pem = pem::parse(&cert_pem)
            .map_err(|e| Error::TrustStore(format!("Failed to parse PEM: {}", e)))?;

        if pem.tag() != "CERTIFICATE" {
            return Err(Error::TrustStore("Invalid PEM type, expected CERTIFICATE".to_string()));
        }

        Ok(pem.contents().to_vec())
    }

    #[cfg(target_os = "windows")]
    fn is_installed(&self) -> Result<bool> {
        let cert_der = self.load_cert_der()?;
        let store = self.open_root_store()?;
        store.has_cert(&cert_der)
    }

    #[cfg(not(target_os = "windows"))]
    fn is_installed(&self) -> Result<bool> {
        Ok(false)
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

    fn has_cert(&self, cert_der: &[u8]) -> Result<bool> {
        unsafe {
            let mut prev_cert: *const CERT_CONTEXT = ptr::null();

            loop {
                prev_cert = CertEnumCertificatesInStore(self.handle, prev_cert);

                if prev_cert.is_null() {
                    break;
                }

                let cert_context = &*prev_cert;
                let stored_cert = std::slice::from_raw_parts(
                    cert_context.pbCertEncoded,
                    cert_context.cbCertEncoded as usize,
                );

                if stored_cert == cert_der {
                    return Ok(true);
                }
            }

            Ok(false)
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
        self.is_installed()
    }

    fn install(&self) -> Result<()> {
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        Ok(())
    }
}
