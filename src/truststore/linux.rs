//! Linux trust store

use crate::Result;
use super::TrustStore;

pub struct LinuxTrustStore;

impl TrustStore for LinuxTrustStore {
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
