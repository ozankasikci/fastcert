//! Windows trust store

use crate::Result;
use super::TrustStore;
use std::path::Path;

#[cfg(target_os = "windows")]
use {
    crate::Error,
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
}

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
