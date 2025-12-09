//! macOS Keychain trust store

use crate::Result;
use super::TrustStore;

pub struct MacOSTrustStore;

impl TrustStore for MacOSTrustStore {
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
