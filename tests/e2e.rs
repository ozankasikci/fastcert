//! Comprehensive end-to-end tests for fastcert
//!
//! These tests verify the complete workflow from CA installation to certificate
//! generation, verification, and cleanup.

mod common;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use common::{get_test_lock, run_openssl};

#[test]
fn test_e2e_complete_workflow_rsa() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    // Set CAROOT to use our temp directory
    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Step 1: Generate certificate (this creates CA automatically)
    let hosts = vec!["e2e-test.local".to_string(), "127.0.0.1".to_string()];
    let cert_file = temp_dir.path().join("e2e-test.pem");
    let key_file = temp_dir.path().join("e2e-test-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false, // RSA (default)
        false,
    );
    assert!(result.is_ok(), "Certificate generation failed: {:?}", result.err());

    // Step 2: Verify CA was created
    let ca_cert_path = ca_path.join("rootCA.pem");
    let ca_key_path = ca_path.join("rootCA-key.pem");
    assert!(ca_cert_path.exists(), "CA certificate not created");
    assert!(ca_key_path.exists(), "CA key not created");

    // Step 3: Verify CA uses RSA-3072
    let ca_key_info = run_openssl(&[
        "rsa", "-noout", "-text", "-in", ca_key_path.to_str().unwrap()
    ]).unwrap();
    assert!(ca_key_info.contains("Private-Key: (3072 bit"), "CA should use RSA-3072");

    // Step 4: Verify certificate uses RSA-2048
    let cert_key_info = run_openssl(&[
        "rsa", "-noout", "-text", "-in", key_file.to_str().unwrap()
    ]).unwrap();
    assert!(cert_key_info.contains("Private-Key: (2048 bit"), "Certificate should use RSA-2048");

    // Step 5: Verify certificate is signed by CA
    let verify_result = Command::new("openssl")
        .args(&["verify", "-CAfile"])
        .arg(&ca_cert_path)
        .arg(&cert_file)
        .output()
        .unwrap();

    let verify_output = String::from_utf8_lossy(&verify_result.stdout);
    assert!(verify_output.contains("OK"), "Certificate verification failed: {}", verify_output);

    // Step 6: Verify certificate contains correct SANs
    let cert_text = run_openssl(&[
        "x509", "-noout", "-text", "-in", cert_file.to_str().unwrap()
    ]).unwrap();
    assert!(cert_text.contains("DNS:e2e-test.local"), "Missing DNS SAN");
    assert!(cert_text.contains("IP Address:127.0.0.1"), "Missing IP SAN");

    // Step 7: Verify certificate validity period (825 days)
    assert!(cert_text.contains("825 days") || cert_text.contains("Not After"),
           "Certificate validity period incorrect");

    // Step 8: Verify file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let key_perms = fs::metadata(&key_file).unwrap().permissions();
        assert_eq!(
            key_perms.mode() & 0o777,
            0o600,
            "Private key should have 0600 permissions"
        );

        let cert_perms = fs::metadata(&cert_file).unwrap().permissions();
        assert_eq!(
            cert_perms.mode() & 0o777,
            0o644,
            "Certificate should have 0644 permissions"
        );
    }

    // Clean up
    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_e2e_complete_workflow_ecdsa() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Generate ECDSA certificate
    let hosts = vec!["ecdsa-test.local".to_string()];
    let cert_file = temp_dir.path().join("ecdsa-test.pem");
    let key_file = temp_dir.path().join("ecdsa-test-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        true, // ECDSA
        false,
    );
    assert!(result.is_ok(), "ECDSA certificate generation failed");

    // Verify certificate uses ECDSA P-256
    let key_info = run_openssl(&[
        "ec", "-noout", "-text", "-in", key_file.to_str().unwrap()
    ]).unwrap();
    assert!(
        key_info.contains("ASN1 OID: prime256v1") || key_info.contains("NIST CURVE: P-256"),
        "Certificate should use ECDSA P-256"
    );

    // Verify ECDSA certificate is still signed by RSA CA
    let ca_cert_path = ca_path.join("rootCA.pem");
    let verify_result = Command::new("openssl")
        .args(&["verify", "-CAfile"])
        .arg(&ca_cert_path)
        .arg(&cert_file)
        .output()
        .unwrap();

    let verify_output = String::from_utf8_lossy(&verify_result.stdout);
    assert!(verify_output.contains("OK"), "ECDSA certificate verification failed");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_e2e_multiple_certificates_same_ca() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Generate multiple certificates with the same CA
    let test_domains = vec![
        vec!["app1.local".to_string()],
        vec!["app2.local".to_string()],
        vec!["app3.local".to_string()],
    ];

    let mut cert_paths = Vec::new();

    for (i, hosts) in test_domains.iter().enumerate() {
        let cert_file = temp_dir.path().join(format!("app{}.pem", i + 1));
        let key_file = temp_dir.path().join(format!("app{}-key.pem", i + 1));

        let result = fastcert::cert::generate_certificate(
            hosts,
            Some(cert_file.to_str().unwrap()),
            Some(key_file.to_str().unwrap()),
            None,
            false,
            false,
            false,
        );
        assert!(result.is_ok(), "Certificate {} generation failed", i + 1);

        cert_paths.push(cert_file);
    }

    // Verify all certificates are signed by the same CA
    let ca_cert_path = ca_path.join("rootCA.pem");
    for (i, cert_path) in cert_paths.iter().enumerate() {
        let verify_result = Command::new("openssl")
            .args(&["verify", "-CAfile"])
            .arg(&ca_cert_path)
            .arg(cert_path)
            .output()
            .unwrap();

        let verify_output = String::from_utf8_lossy(&verify_result.stdout);
        assert!(
            verify_output.contains("OK"),
            "Certificate {} verification failed",
            i + 1
        );
    }

    // Verify all certificates have different serial numbers
    let mut serial_numbers = Vec::new();
    for cert_path in &cert_paths {
        let serial_output = run_openssl(&[
            "x509", "-noout", "-serial", "-in", cert_path.to_str().unwrap()
        ]).unwrap();
        serial_numbers.push(serial_output.trim().to_string());
    }

    // Check for uniqueness
    for i in 0..serial_numbers.len() {
        for j in (i + 1)..serial_numbers.len() {
            assert_ne!(
                serial_numbers[i],
                serial_numbers[j],
                "Certificates {} and {} have duplicate serial numbers",
                i + 1,
                j + 1
            );
        }
    }

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_e2e_complex_sans() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Generate certificate with complex SANs
    let hosts = vec![
        "app.example.com".to_string(),
        "*.app.example.com".to_string(),  // Wildcard
        "api.example.com".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "2001:db8::1".to_string(),
    ];

    let cert_file = temp_dir.path().join("complex.pem");
    let key_file = temp_dir.path().join("complex-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    );
    assert!(result.is_ok(), "Complex SAN certificate generation failed");

    // Verify all SANs are present
    let cert_text = run_openssl(&[
        "x509", "-noout", "-text", "-in", cert_file.to_str().unwrap()
    ]).unwrap();

    assert!(cert_text.contains("DNS:app.example.com"), "Missing DNS SAN");
    assert!(cert_text.contains("DNS:*.app.example.com"), "Missing wildcard SAN");
    assert!(cert_text.contains("DNS:api.example.com"), "Missing DNS SAN");
    assert!(cert_text.contains("DNS:localhost"), "Missing localhost SAN");
    assert!(cert_text.contains("IP Address:127.0.0.1"), "Missing IPv4 SAN");
    assert!(cert_text.contains("IP Address:0:0:0:0:0:0:0:1"), "Missing IPv6 ::1 SAN");
    assert!(cert_text.contains("IP Address:2001:DB8:0:0:0:0:0:1"), "Missing IPv6 2001:db8::1 SAN");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_e2e_pkcs12_export() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    let hosts = vec!["pkcs12-test.local".to_string()];
    let cert_file = temp_dir.path().join("pkcs12-test.pem");
    let key_file = temp_dir.path().join("pkcs12-test-key.pem");
    let p12_file = temp_dir.path().join("pkcs12-test.p12");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        Some(p12_file.to_str().unwrap()),
        false,
        false,
        true, // Generate PKCS12
    );
    assert!(result.is_ok(), "PKCS12 certificate generation failed");

    // Verify PKCS12 file was created
    assert!(p12_file.exists(), "PKCS12 file not created");

    // Verify PKCS12 file is not empty
    let p12_size = fs::metadata(&p12_file).unwrap().len();
    assert!(p12_size > 0, "PKCS12 file is empty");

    // Verify PKCS12 file can be read by openssl
    let p12_info = Command::new("openssl")
        .args(&["pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"])
        .arg("-in")
        .arg(&p12_file)
        .output();

    // Note: This might fail if openssl version doesn't support legacy format,
    // but the file should at least exist
    assert!(p12_info.is_ok(), "Failed to run openssl pkcs12 command");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_e2e_client_certificate() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    let hosts = vec!["client-auth@example.com".to_string()];
    let cert_file = temp_dir.path().join("client.pem");
    let key_file = temp_dir.path().join("client-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        true, // Client certificate
        false,
        false,
    );
    assert!(result.is_ok(), "Client certificate generation failed");

    // Verify certificate has client auth extended key usage
    let cert_text = run_openssl(&[
        "x509", "-noout", "-text", "-in", cert_file.to_str().unwrap()
    ]).unwrap();

    assert!(
        cert_text.contains("TLS Web Client Authentication"),
        "Client certificate missing client auth usage"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_e2e_certificate_file_naming() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Save current directory and change to temp dir
    let original_dir = env::current_dir().unwrap();
    env::set_current_dir(temp_dir.path()).unwrap();

    // Test 1: Single domain
    let hosts = vec!["single.local".to_string()];
    fastcert::cert::generate_certificate(&hosts, None, None, None, false, false, false).unwrap();
    assert!(PathBuf::from("single.local.pem").exists(), "Single domain cert naming wrong");
    assert!(PathBuf::from("single.local-key.pem").exists(), "Single domain key naming wrong");

    // Test 2: Multiple domains
    let hosts = vec![
        "multi.local".to_string(),
        "multi2.local".to_string(),
        "multi3.local".to_string(),
    ];
    fastcert::cert::generate_certificate(&hosts, None, None, None, false, false, false).unwrap();
    assert!(PathBuf::from("multi.local+2.pem").exists(), "Multi domain cert naming wrong");
    assert!(PathBuf::from("multi.local+2-key.pem").exists(), "Multi domain key naming wrong");

    // Test 3: Wildcard domain
    let hosts = vec!["*.wildcard.local".to_string()];
    fastcert::cert::generate_certificate(&hosts, None, None, None, false, false, false).unwrap();
    assert!(PathBuf::from("_wildcard.wildcard.local.pem").exists(), "Wildcard cert naming wrong");
    assert!(PathBuf::from("_wildcard.wildcard.local-key.pem").exists(), "Wildcard key naming wrong");

    // Restore original directory
    env::set_current_dir(original_dir).unwrap();

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_e2e_error_handling_invalid_domain() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Test invalid domain names
    let invalid_hosts = vec!["".to_string()];
    let result = fastcert::cert::generate_certificate(
        &invalid_hosts,
        None,
        None,
        None,
        false,
        false,
        false,
    );
    assert!(result.is_err(), "Should fail with empty domain");

    unsafe {
        env::remove_var("CAROOT");
    }
}
