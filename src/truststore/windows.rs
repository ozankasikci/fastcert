//! Windows trust store

use crate::Result;
use super::TrustStore;

pub struct WindowsTrustStore;

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
