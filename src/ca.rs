//! Certificate Authority management

use crate::{Error, Result};
use std::path::{Path, PathBuf};
use rcgen::Certificate;

const ROOT_CERT_FILE: &str = "rootCA.pem";
const ROOT_KEY_FILE: &str = "rootCA-key.pem";

pub struct CertificateAuthority {
    root_path: PathBuf,
    cert: Option<Certificate>,
    cert_pem: Option<String>,
}

impl CertificateAuthority {
    pub fn new(root_path: PathBuf) -> Self {
        Self {
            root_path,
            cert: None,
            cert_pem: None,
        }
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub fn cert_path(&self) -> PathBuf {
        self.root_path.join(ROOT_CERT_FILE)
    }

    pub fn key_path(&self) -> PathBuf {
        self.root_path.join(ROOT_KEY_FILE)
    }

    pub fn cert_exists(&self) -> bool {
        self.cert_path().exists()
    }

    pub fn key_exists(&self) -> bool {
        self.key_path().exists()
    }
}
