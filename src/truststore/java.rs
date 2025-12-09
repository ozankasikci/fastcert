//! Java keystore

use crate::Result;
use super::TrustStore;

pub struct JavaTrustStore;

impl TrustStore for JavaTrustStore {
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
