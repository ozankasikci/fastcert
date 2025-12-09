//! Certificate Authority management

use crate::{Error, Result};
use std::path::PathBuf;

pub struct CertificateAuthority {
    root_path: PathBuf,
}

impl CertificateAuthority {
    pub fn new(root_path: PathBuf) -> Self {
        Self { root_path }
    }
}
