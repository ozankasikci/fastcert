//! Linux trust store

use crate::{Error, Result};
use super::TrustStore;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Supported Linux distributions
#[derive(Debug, Clone, Copy, PartialEq)]
enum LinuxDistro {
    /// RHEL, Fedora, CentOS - uses update-ca-trust
    RedHat,
    /// Debian, Ubuntu - uses update-ca-certificates
    Debian,
    /// Arch Linux - uses trust command
    Arch,
    /// OpenSUSE - uses update-ca-certificates
    OpenSUSE,
    /// Unknown distribution
    Unknown,
}

impl LinuxDistro {
    /// Detect the Linux distribution by checking for existence of update commands
    fn detect() -> Self {
        // Check for RHEL/Fedora/CentOS (update-ca-trust)
        if Path::new("/etc/pki/ca-trust/source/anchors/").exists() {
            return Self::RedHat;
        }

        // Check for Debian/Ubuntu (update-ca-certificates)
        if Path::new("/usr/local/share/ca-certificates/").exists() {
            return Self::Debian;
        }

        // Check for Arch Linux (trust extract-compat)
        if Path::new("/etc/ca-certificates/trust-source/anchors/").exists() {
            return Self::Arch;
        }

        // Check for OpenSUSE (update-ca-certificates)
        if Path::new("/usr/share/pki/trust/anchors").exists() {
            return Self::OpenSUSE;
        }

        Self::Unknown
    }
}

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
