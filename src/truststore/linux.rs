//! Linux trust store

use super::TrustStore;
use crate::{Error, Result};
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

    /// Get the certificate directory path for this distribution
    fn cert_dir(&self) -> Option<&'static str> {
        match self {
            Self::RedHat => Some("/etc/pki/ca-trust/source/anchors/"),
            Self::Debian => Some("/usr/local/share/ca-certificates/"),
            Self::Arch => Some("/etc/ca-certificates/trust-source/anchors/"),
            Self::OpenSUSE => Some("/usr/share/pki/trust/anchors/"),
            Self::Unknown => None,
        }
    }

    /// Get the certificate file extension for this distribution
    fn cert_extension(&self) -> &'static str {
        match self {
            Self::RedHat | Self::OpenSUSE => "pem",
            Self::Debian | Self::Arch => "crt",
            Self::Unknown => "pem",
        }
    }

    /// Get the certificate file path for a given name
    fn cert_path(&self, cert_name: &str) -> Option<PathBuf> {
        let dir = self.cert_dir()?;
        let ext = self.cert_extension();
        Some(PathBuf::from(format!("{}{}.{}", dir, cert_name, ext)))
    }

    /// Get the update command for this distribution
    fn update_command(&self) -> Option<Vec<&'static str>> {
        match self {
            Self::RedHat => Some(vec!["update-ca-trust", "extract"]),
            Self::Debian | Self::OpenSUSE => Some(vec!["update-ca-certificates"]),
            Self::Arch => Some(vec!["trust", "extract-compat"]),
            Self::Unknown => None,
        }
    }
}

pub struct LinuxTrustStore {
    cert_path: PathBuf,
    distro: LinuxDistro,
}

impl LinuxTrustStore {
    pub fn new(cert_path: &Path) -> Self {
        Self {
            cert_path: cert_path.to_path_buf(),
            distro: LinuxDistro::detect(),
        }
    }

    /// Get the system trust store path for the certificate
    fn system_cert_path(&self) -> Option<PathBuf> {
        self.distro.cert_path("fastcert-rootCA")
    }

    /// Run a command with sudo if needed
    fn run_with_sudo(&self, args: &[&str]) -> Result<std::process::Output> {
        let output = Command::new("sudo")
            .args(args)
            .output()
            .map_err(|e| Error::CommandFailed(format!("Failed to execute sudo command: {}", e)))?;

        Ok(output)
    }
}

impl TrustStore for LinuxTrustStore {
    fn check(&self) -> Result<bool> {
        // Check if the distribution is supported
        if self.distro == LinuxDistro::Unknown {
            return Ok(false);
        }

        // Check if the certificate file exists in the system trust store
        if let Some(sys_path) = self.system_cert_path() {
            Ok(sys_path.exists())
        } else {
            Ok(false)
        }
    }

    fn install(&self) -> Result<()> {
        // Check if distribution is supported
        if self.distro == LinuxDistro::Unknown {
            println!(
                "Installing to the system store is not yet supported on this Linux distribution."
            );
            println!(
                "You can manually install the root certificate at {:?}",
                self.cert_path
            );
            return Ok(());
        }

        // Check if already installed
        if self.check()? {
            println!("The local CA certificate is already installed in the system trust store.");
            return Ok(());
        }

        println!("Installing CA certificate to Linux system trust store...");
        println!("Note: This will require administrator privileges.");

        // Get the target path
        let sys_path = self.system_cert_path().ok_or_else(|| {
            Error::TrustStore("Failed to determine system certificate path".to_string())
        })?;

        // Read the certificate
        let cert_content = std::fs::read(&self.cert_path)
            .map_err(|e| Error::TrustStore(format!("Failed to read certificate: {}", e)))?;

        // Copy certificate to system trust store using tee
        let sys_path_str = sys_path.to_string_lossy();
        let output = Command::new("sudo")
            .arg("tee")
            .arg(sys_path_str.as_ref())
            .stdin(std::process::Stdio::piped())
            .output()
            .map_err(|e| Error::CommandFailed(format!("Failed to execute tee command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::TrustStore(format!(
                "Failed to copy certificate to system trust store: {}",
                stderr
            )));
        }

        // Write the certificate content
        let mut child = Command::new("sudo")
            .arg("tee")
            .arg(sys_path_str.as_ref())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .map_err(|e| Error::CommandFailed(format!("Failed to spawn tee command: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(&cert_content)
                .map_err(|e| Error::TrustStore(format!("Failed to write certificate: {}", e)))?;
        }

        let status = child
            .wait()
            .map_err(|e| Error::CommandFailed(format!("Failed to wait for tee command: {}", e)))?;

        if !status.success() {
            return Err(Error::TrustStore(
                "Failed to copy certificate to system trust store".to_string(),
            ));
        }

        // Run the update command for the distribution
        if let Some(update_cmd) = self.distro.update_command() {
            let output = self.run_with_sudo(&update_cmd)?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::TrustStore(format!(
                    "Failed to update system trust store: {}",
                    stderr
                )));
            }
        }

        println!("The local CA certificate is now installed in the system trust store.");
        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        // Check if distribution is supported
        if self.distro == LinuxDistro::Unknown {
            println!("The local CA certificate is not installed in the system trust store.");
            return Ok(());
        }

        // Check if not installed
        if !self.check()? {
            println!("The local CA certificate is not installed in the system trust store.");
            return Ok(());
        }

        println!("Removing CA certificate from Linux system trust store...");
        println!("Note: This will require administrator privileges.");

        // Get the target path
        let sys_path = self.system_cert_path().ok_or_else(|| {
            Error::TrustStore("Failed to determine system certificate path".to_string())
        })?;

        // Remove the certificate file
        let sys_path_str = sys_path.to_string_lossy();
        let output = self.run_with_sudo(&["rm", "-f", sys_path_str.as_ref()])?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::TrustStore(format!(
                "Failed to remove certificate from system trust store: {}",
                stderr
            )));
        }

        // Run the update command for the distribution
        if let Some(update_cmd) = self.distro.update_command() {
            let output = self.run_with_sudo(&update_cmd)?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::TrustStore(format!(
                    "Failed to update system trust store: {}",
                    stderr
                )));
            }
        }

        println!("The local CA certificate has been removed from the system trust store.");
        Ok(())
    }
}
