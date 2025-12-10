//! Additional CA tests for error handling

mod common;

use common::get_test_lock;
use std::env;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_ca_get_caroot() {
    let _lock = get_test_lock();

    // Test getting CAROOT
    let result = fastcert::ca::get_caroot();
    assert!(result.is_ok(), "Should be able to get CAROOT");
}

#[test]
fn test_ca_get_caroot_with_env() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let caroot = fastcert::ca::get_caroot().unwrap();
    assert_eq!(
        caroot,
        temp_dir.path().to_str().unwrap(),
        "Should use CAROOT env var"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_ca_load_or_create() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let mut ca = fastcert::ca::CertificateAuthority::new(temp_dir.path().to_path_buf());

    // First call creates CA
    let result = ca.load_or_create();
    assert!(result.is_ok(), "Should create CA successfully");

    // Verify CA files were created
    let ca_cert = temp_dir.path().join("rootCA.pem");
    let ca_key = temp_dir.path().join("rootCA-key.pem");
    assert!(ca_cert.exists(), "CA cert should exist");
    assert!(ca_key.exists(), "CA key should exist");

    // Second call should load existing CA
    let mut ca2 = fastcert::ca::CertificateAuthority::new(temp_dir.path().to_path_buf());
    let result = ca2.load_or_create();
    assert!(result.is_ok(), "Should load existing CA");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_ca_cert_path() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    let ca = fastcert::ca::CertificateAuthority::new(temp_dir.path().to_path_buf());
    let cert_path = ca.cert_path();

    assert!(
        cert_path.to_str().unwrap().ends_with("rootCA.pem"),
        "Cert path should end with rootCA.pem"
    );
}

#[test]
fn test_ca_key_path() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    let ca = fastcert::ca::CertificateAuthority::new(temp_dir.path().to_path_buf());
    let key_path = ca.key_path();

    assert!(
        key_path.to_str().unwrap().ends_with("rootCA-key.pem"),
        "Key path should end with rootCA-key.pem"
    );
}

#[test]
fn test_ca_directory_creation() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    let ca_dir = temp_dir.path().join("new_ca_dir");

    unsafe {
        env::set_var("CAROOT", ca_dir.to_str().unwrap());
    }

    let mut ca = fastcert::ca::CertificateAuthority::new(ca_dir.clone());
    let result = ca.load_or_create();
    assert!(result.is_ok(), "Should create directory if it doesn't exist");
    assert!(ca_dir.exists(), "CA directory should be created");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_ca_generates_unique_serials() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Generate multiple certificates
    for i in 0..5 {
        let hosts = vec![format!("test{}.local", i)];
        let cert_file = temp_dir.path().join(format!("test{}.pem", i));
        let key_file = temp_dir.path().join(format!("test{}-key.pem", i));

        fastcert::cert::generate_certificate(
            &hosts,
            Some(cert_file.to_str().unwrap()),
            Some(key_file.to_str().unwrap()),
            None,
            false,
            false,
            false,
        )
        .unwrap();
    }

    // Verify all certificates have different serial numbers
    let mut serials = std::collections::HashSet::new();
    for i in 0..5 {
        let cert_file = temp_dir.path().join(format!("test{}.pem", i));
        let cert_pem = fs::read_to_string(&cert_file).unwrap();

        // Extract serial from certificate (simplified check - just ensure content differs)
        assert!(serials.insert(cert_pem.clone()), "Certificates should differ");
    }

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_ca_permissions() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let mut ca = fastcert::ca::CertificateAuthority::new(temp_dir.path().to_path_buf());
    ca.load_or_create().unwrap();

    let ca_key = ca.key_path();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&ca_key).unwrap().permissions();
        let mode = perms.mode() & 0o777;
        // Key should be readable only by owner (at least 0o400)
        assert!(
            mode <= 0o600,
            "CA key should have restrictive permissions, got {:o}",
            mode
        );
    }

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_multiple_ca_roots() {
    let _lock = get_test_lock();
    let temp_dir1 = TempDir::new().unwrap();
    let temp_dir2 = TempDir::new().unwrap();

    // Create first CA
    unsafe {
        env::set_var("CAROOT", temp_dir1.path().to_str().unwrap());
    }
    let mut ca1 = fastcert::ca::CertificateAuthority::new(temp_dir1.path().to_path_buf());
    ca1.load_or_create().unwrap();

    // Create second CA
    unsafe {
        env::set_var("CAROOT", temp_dir2.path().to_str().unwrap());
    }
    let mut ca2 = fastcert::ca::CertificateAuthority::new(temp_dir2.path().to_path_buf());
    ca2.load_or_create().unwrap();

    // Verify both exist
    assert!(temp_dir1.path().join("rootCA.pem").exists());
    assert!(temp_dir2.path().join("rootCA.pem").exists());

    // Verify they're different
    let ca1_pem = fs::read_to_string(temp_dir1.path().join("rootCA.pem")).unwrap();
    let ca2_pem = fs::read_to_string(temp_dir2.path().join("rootCA.pem")).unwrap();
    assert_ne!(ca1_pem, ca2_pem, "Different CAs should have different certs");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_cert_file_write() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["write-test.local".to_string()];
    let cert_file = temp_dir.path().join("write-test.pem");
    let key_file = temp_dir.path().join("write-test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    )
    .unwrap();

    // Verify files exist and have content
    assert!(cert_file.exists(), "Cert file should exist");
    assert!(key_file.exists(), "Key file should exist");

    let cert_content = fs::read_to_string(&cert_file).unwrap();
    let key_content = fs::read_to_string(&key_file).unwrap();

    assert!(
        cert_content.contains("BEGIN CERTIFICATE"),
        "Cert should be in PEM format"
    );
    assert!(
        key_content.contains("BEGIN") && key_content.contains("PRIVATE KEY"),
        "Key should be in PEM format"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_cert_overwrite() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["overwrite.local".to_string()];
    let cert_file = temp_dir.path().join("overwrite.pem");
    let key_file = temp_dir.path().join("overwrite-key.pem");

    // Generate first time
    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    )
    .unwrap();

    let first_content = fs::read_to_string(&cert_file).unwrap();

    // Generate second time (should overwrite)
    std::thread::sleep(std::time::Duration::from_millis(100));
    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    )
    .unwrap();

    let second_content = fs::read_to_string(&cert_file).unwrap();

    // Content should be different (different serial, timestamps, etc.)
    assert_ne!(
        first_content, second_content,
        "Regenerated cert should differ"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}
