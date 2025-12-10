//! Windows trust store

use super::TrustStore;
use crate::{Error, Result};
use std::path::Path;

#[cfg(target_os = "windows")]
use {
    std::ptr,
    windows::Win32::Foundation::GetLastError,
    windows::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W,
        CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
        CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertOpenSystemStoreW,
        HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    },
    windows::core::PCWSTR,
};

#[cfg(target_os = "windows")]
fn windows_error_string(error: windows::core::Error) -> String {
    format!(
        "Windows error 0x{:08X}: {}",
        error.code().0,
        error.message()
    )
}

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
        Err(Error::TrustStore(
            "Windows trust store is only available on Windows".to_string(),
        ))
    }

    fn load_cert_der(&self) -> Result<Vec<u8>> {
        let cert_pem = std::fs::read_to_string(&self.cert_path)
            .map_err(|e| Error::TrustStore(format!("Failed to read certificate: {}", e)))?;

        let pem = pem::parse(&cert_pem)
            .map_err(|e| Error::TrustStore(format!("Failed to parse PEM: {}", e)))?;

        if pem.tag() != "CERTIFICATE" {
            return Err(Error::TrustStore(
                "Invalid PEM type, expected CERTIFICATE".to_string(),
            ));
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
            let handle = CertOpenSystemStoreW(None, PCWSTR(store_name.as_ptr())).map_err(|e| {
                Error::TrustStore(format!(
                    "Failed to open Windows root store: {}",
                    windows_error_string(e)
                ))
            })?;

            if handle.is_invalid() {
                let error = GetLastError();
                return Err(Error::TrustStore(format!(
                    "Failed to open Windows root store: Invalid handle (error code: {:?})",
                    error
                )));
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

    fn add_cert(&self, cert_der: &[u8]) -> Result<()> {
        unsafe {
            let result = CertAddEncodedCertificateToStore(
                self.handle,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert_der,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            )
            .map_err(|e| {
                let err_msg = windows_error_string(e);
                if err_msg.contains("0x80092003")
                    || err_msg.contains("access")
                    || err_msg.contains("denied")
                {
                    Error::TrustStore(format!(
                        "Access denied when adding certificate. Please run as administrator: {}",
                        err_msg
                    ))
                } else {
                    Error::TrustStore(format!("Failed to add certificate: {}", err_msg))
                }
            })?;

            if !result.as_bool() {
                return Err(Error::TrustStore(
                    "Failed to add certificate to store: Operation returned failure".to_string(),
                ));
            }

            Ok(())
        }
    }

    fn delete_cert(&self, cert_der: &[u8]) -> Result<bool> {
        unsafe {
            let mut prev_cert: *const CERT_CONTEXT = ptr::null();
            let mut deleted_any = false;

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
                    // Duplicate the context so it doesn't stop enumeration when we delete it
                    let dup_cert =
                        CertDuplicateCertificateContext(Some(prev_cert)).map_err(|e| {
                            Error::TrustStore(format!(
                                "Failed to duplicate certificate context: {}",
                                windows_error_string(e)
                            ))
                        })?;

                    if dup_cert.is_null() {
                        return Err(Error::TrustStore(
                            "Failed to duplicate certificate context: Null pointer returned"
                                .to_string(),
                        ));
                    }

                    CertDeleteCertificateFromStore(dup_cert).map_err(|e| {
                        let err_msg = windows_error_string(e);
                        if err_msg.contains("0x80092003") || err_msg.contains("access") || err_msg.contains("denied") {
                            Error::TrustStore(format!(
                                "Access denied when deleting certificate. Please run as administrator: {}",
                                err_msg
                            ))
                        } else {
                            Error::TrustStore(format!("Failed to delete certificate: {}", err_msg))
                        }
                    })?;

                    deleted_any = true;
                }
            }

            Ok(deleted_any)
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

    #[cfg(target_os = "windows")]
    fn install(&self) -> Result<()> {
        if self.is_installed()? {
            println!(
                "The local CA certificate is already installed in the Windows certificate store."
            );
            return Ok(());
        }

        println!("Installing CA certificate to Windows certificate store...");
        println!("Note: This will require administrator privileges.");

        let cert_der = self.load_cert_der()?;
        let store = self.open_root_store()?;
        store.add_cert(&cert_der)?;

        println!("The local CA certificate is now installed in the Windows certificate store.");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn install(&self) -> Result<()> {
        Err(Error::TrustStore(
            "Windows trust store is only available on Windows".to_string(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn uninstall(&self) -> Result<()> {
        if !self.is_installed()? {
            println!("The local CA certificate is not installed in the Windows certificate store.");
            return Ok(());
        }

        println!("Removing CA certificate from Windows certificate store...");
        println!("Note: This will require administrator privileges.");

        let cert_der = self.load_cert_der()?;
        let store = self.open_root_store()?;
        let deleted = store.delete_cert(&cert_der)?;

        if !deleted {
            return Err(Error::TrustStore(
                "Failed to find and remove certificate".to_string(),
            ));
        }

        println!("The local CA certificate has been removed from the Windows certificate store.");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn uninstall(&self) -> Result<()> {
        Err(Error::TrustStore(
            "Windows trust store is only available on Windows".to_string(),
        ))
    }
}
