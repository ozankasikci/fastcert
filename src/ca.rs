//! Certificate Authority management

use crate::{Error, Result};
use std::path::PathBuf;

const ROOT_CERT_FILE: &str = "rootCA.pem";
const ROOT_KEY_FILE: &str = "rootCA-key.pem";

pub struct CertificateAuthority {
    root_path: PathBuf,
}

impl CertificateAuthority {
    pub fn new(root_path: PathBuf) -> Self {
        Self { root_path }
    }
}
