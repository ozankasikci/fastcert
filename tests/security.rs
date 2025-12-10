//! Security-focused tests for fastcert
//!
//! These tests verify security properties like file permissions, key security,
//! certificate validation, and error handling.

mod common;

use std::env;
use std::fs;
use tempfile::TempDir;
use common::get_test_lock;

#[test]
#[cfg(unix)]
fn test_security_private_key_permissions() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["security-test.local".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    ).unwrap();

    // Verify private key has restrictive permissions (0600)
    use std::os::unix::fs::PermissionsExt;
    let key_perms = fs::metadata(&key_file).unwrap().permissions();
    let mode = key_perms.mode() & 0o777;

    assert_eq!(
        mode, 0o600,
        "Private key should have 0600 permissions, got {:o}",
        mode
    );

    // Verify CA private key also has restrictive permissions (0400 or 0600)
    let ca_key = temp_dir.path().join("rootCA-key.pem");
    let ca_key_perms = fs::metadata(&ca_key).unwrap().permissions();
    let ca_mode = ca_key_perms.mode() & 0o777;

    assert!(
        ca_mode == 0o400 || ca_mode == 0o600,
        "CA private key should have 0400 or 0600 permissions, got {:o}",
        ca_mode
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_security_certificate_not_self_signed() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["not-self-signed.local".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    ).unwrap();

    // Read certificate and verify it's signed by CA
    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-issuer", "-subject"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&output.stdout);

    // Certificate should have different issuer and subject
    assert!(text.contains("issuer="), "Should have issuer field");
    assert!(text.contains("subject="), "Should have subject field");

    // Issuer should contain "mkcert" (CA name)
    assert!(text.contains("mkcert"), "Should be signed by mkcert CA");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_security_unique_serial_numbers() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Generate multiple certificates
    let mut serials = Vec::new();

    for i in 1..=5 {
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
        ).unwrap();

        // Get serial number
        use std::process::Command;
        let output = Command::new("openssl")
            .args(&["x509", "-noout", "-serial"])
            .arg("-in")
            .arg(&cert_file)
            .output()
            .unwrap();

        let serial = String::from_utf8_lossy(&output.stdout).trim().to_string();
        serials.push(serial);
    }

    // Verify all serials are unique
    for i in 0..serials.len() {
        for j in (i + 1)..serials.len() {
            assert_ne!(
                serials[i],
                serials[j],
                "Certificates {} and {} have duplicate serial numbers: {}",
                i + 1,
                j + 1,
                serials[i]
            );
        }
    }

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_security_ca_certificate_validity() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Generate a certificate (creates CA)
    let hosts = vec!["test.local".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    ).unwrap();

    // Verify CA certificate properties
    use std::process::Command;
    let ca_cert = temp_dir.path().join("rootCA.pem");
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-text"])
        .arg("-in")
        .arg(&ca_cert)
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&output.stdout);

    // CA should have CA:TRUE basic constraint
    assert!(text.contains("CA:TRUE"), "CA certificate should have CA:TRUE");

    // CA should be able to sign certificates
    assert!(text.contains("Certificate Sign"), "CA should have Certificate Sign usage");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_error_empty_host_list() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec![];
    let result = fastcert::cert::generate_certificate(
        &hosts,
        None,
        None,
        None,
        false,
        false,
        false,
    );

    assert!(result.is_err(), "Should fail with empty host list");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_error_invalid_wildcard() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Test double wildcard (should fail)
    let hosts = vec!["**.example.com".to_string()];
    let result = fastcert::cert::generate_certificate(
        &hosts,
        None,
        None,
        None,
        false,
        false,
        false,
    );

    assert!(result.is_err(), "Should fail with double wildcard");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_certificate_expiration_date() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["expiry-test.local".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    ).unwrap();

    // Verify certificate validity period
    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-dates"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();

    let dates = String::from_utf8_lossy(&output.stdout);

    // Should have both notBefore and notAfter
    assert!(dates.contains("notBefore="), "Certificate should have notBefore date");
    assert!(dates.contains("notAfter="), "Certificate should have notAfter date");

    // Verify it's currently valid
    let verify_output = Command::new("openssl")
        .args(&["x509", "-noout", "-checkend", "0"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();

    assert!(
        verify_output.status.success(),
        "Certificate should be currently valid"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_certificate_key_usage() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Test server certificate
    let hosts = vec!["server.local".to_string()];
    let cert_file = temp_dir.path().join("server.pem");
    let key_file = temp_dir.path().join("server-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    ).unwrap();

    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-text"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&output.stdout);

    // Server certificate should have TLS Web Server Authentication
    assert!(
        text.contains("TLS Web Server Authentication"),
        "Server certificate should have server auth usage"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_client_certificate_key_usage() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Test client certificate
    let hosts = vec!["client@example.com".to_string()];
    let cert_file = temp_dir.path().join("client.pem");
    let key_file = temp_dir.path().join("client-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        true, // Client cert
        false,
        false,
    ).unwrap();

    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-text"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&output.stdout);

    // Client certificate should have TLS Web Client Authentication
    assert!(
        text.contains("TLS Web Client Authentication"),
        "Client certificate should have client auth usage"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_san_types_validation() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Test various SAN types
    let hosts = vec![
        "dns.example.com".to_string(),
        "192.168.1.1".to_string(),
        "email@example.com".to_string(),
    ];

    let cert_file = temp_dir.path().join("san.pem");
    let key_file = temp_dir.path().join("san-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    );

    assert!(result.is_ok(), "Should handle mixed SAN types");

    // Verify all SANs are present
    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-text"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&output.stdout);

    assert!(text.contains("DNS:dns.example.com"), "Should contain DNS SAN");
    assert!(text.contains("IP Address:192.168.1.1"), "Should contain IP SAN");
    assert!(text.contains("email:email@example.com"), "Should contain email SAN");

    unsafe {
        env::remove_var("CAROOT");
    }
}
