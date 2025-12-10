//! Common test utilities shared across all test suites

use std::process::Command;
use std::sync::Mutex;

/// Global test lock to ensure tests run serially (they modify global env vars)
pub static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Helper to get lock even if poisoned (tests may panic)
pub fn get_test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Helper function to run openssl commands and return output
pub fn run_openssl(args: &[&str]) -> Result<String, String> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run openssl: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "OpenSSL command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Verify certificate is signed by CA using openssl
pub fn verify_cert_with_ca(cert_path: &std::path::Path, ca_cert_path: &std::path::Path) -> bool {
    let output = Command::new("openssl")
        .args(&["verify", "-CAfile"])
        .arg(ca_cert_path)
        .arg(cert_path)
        .output();

    match output {
        Ok(out) => {
            let result = String::from_utf8_lossy(&out.stdout);
            result.contains("OK")
        }
        Err(_) => false,
    }
}

/// Get certificate serial number
pub fn get_cert_serial(cert_path: &std::path::Path) -> Result<String, String> {
    run_openssl(&["x509", "-noout", "-serial", "-in", cert_path.to_str().unwrap()])
        .map(|s| s.trim().to_string())
}

/// Get certificate text (full details)
pub fn get_cert_text(cert_path: &std::path::Path) -> Result<String, String> {
    run_openssl(&["x509", "-noout", "-text", "-in", cert_path.to_str().unwrap()])
}

/// Check if certificate contains a specific SAN
pub fn cert_contains_san(cert_path: &std::path::Path, san: &str) -> Result<bool, String> {
    let text = get_cert_text(cert_path)?;
    Ok(text.contains(san))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_works() {
        let _lock = get_test_lock();
        // Should not panic even if another test panicked with lock
    }
}
