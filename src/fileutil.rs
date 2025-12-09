//! File and path utilities

use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Get the CAROOT directory path
pub fn get_ca_root() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("CAROOT") {
        return Ok(PathBuf::from(path));
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join("Library/Application Support/mkcert"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_app_data) = dirs::data_local_dir() {
            return Ok(local_app_data.join("mkcert"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return Ok(PathBuf::from(xdg).join("mkcert"));
        }
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".local/share/mkcert"));
        }
    }

    Err(Error::CARootNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ca_root() {
        let result = get_ca_root();
        assert!(result.is_ok());
    }
}
