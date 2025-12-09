//! NSS/Firefox trust store

use crate::Result;
use super::TrustStore;

pub struct NssTrustStore;

impl TrustStore for NssTrustStore {
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
