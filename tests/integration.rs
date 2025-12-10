//! Integration tests for certificate signing and key size verification

mod common;

use common::get_test_lock;
use std::env;
use tempfile::TempDir;

#[test]
fn test_certificate_is_signed_by_ca() {
    let _lock = get_test_lock();
    // Setup: Create a temporary CA
    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    // Set CAROOT to use our temp directory
    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Generate a certificate - this will create the CA automatically
    let hosts = vec!["test.local".to_string(), "127.0.0.1".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,  // p12_file
        false, // client cert
        false, // use ECDSA (default: RSA)
        false, // pkcs12
    )
    .unwrap();

    // Parse certificates using openssl command
    use std::process::Command;

    // Get certificate issuer
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-issuer"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();
    let cert_issuer = String::from_utf8_lossy(&output.stdout);

    // Get CA subject
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-subject"])
        .arg("-in")
        .arg(ca_path.join("rootCA.pem"))
        .output()
        .unwrap();
    let ca_subject = String::from_utf8_lossy(&output.stdout);
    let ca_subject_err = String::from_utf8_lossy(&output.stderr);

    // The certificate's issuer should match the CA's subject
    println!("Certificate Issuer: {}", cert_issuer);
    println!("CA Subject: {}", ca_subject);
    if !ca_subject_err.is_empty() {
        println!("CA Subject Error: {}", ca_subject_err);
    }

    // Extract the CN from both
    assert!(
        cert_issuer.contains("mkcert"),
        "Certificate should be signed by mkcert CA, got: {}",
        cert_issuer
    );
    assert!(
        !cert_issuer.contains("rcgen self signed"),
        "Certificate should NOT be self-signed by rcgen"
    );

    // Verify certificate chain
    let output = Command::new("openssl")
        .args(&["verify", "-CAfile"])
        .arg(ca_path.join("rootCA.pem"))
        .arg(&cert_file)
        .output()
        .unwrap();

    let verify_result = String::from_utf8_lossy(&output.stdout);
    let verify_err = String::from_utf8_lossy(&output.stderr);
    println!("Verification stdout: {}", verify_result);
    if !verify_err.is_empty() {
        println!("Verification stderr: {}", verify_err);
    }
    assert!(
        verify_result.contains("OK"),
        "Certificate should verify against CA, got: {} (stderr: {})",
        verify_result,
        verify_err
    );

    // Clean up
    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_certificate_contains_correct_sans() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    // Set CAROOT to use our temp directory
    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    let hosts = vec![
        "example.com".to_string(),
        "*.example.com".to_string(),
        "192.168.1.1".to_string(),
        "::1".to_string(),
    ];

    let cert_file = temp_dir.path().join("multi.pem");
    let key_file = temp_dir.path().join("multi-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,  // p12_file
        false, // client cert
        false, // use ECDSA (default: RSA)
        false, // pkcs12
    )
    .unwrap();

    // Verify SANs using openssl
    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["x509", "-noout", "-text"])
        .arg("-in")
        .arg(&cert_file)
        .output()
        .unwrap();

    let cert_text = String::from_utf8_lossy(&output.stdout);

    assert!(
        cert_text.contains("DNS:example.com"),
        "Should contain example.com"
    );
    assert!(
        cert_text.contains("DNS:*.example.com"),
        "Should contain wildcard"
    );
    assert!(
        cert_text.contains("IP Address:192.168.1.1"),
        "Should contain IPv4"
    );
    assert!(
        cert_text.contains("IP Address:0:0:0:0:0:0:0:1"),
        "Should contain IPv6"
    );

    // Clean up
    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_ca_uses_rsa_3072() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    // Set CAROOT to use our temp directory
    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    // Generate a certificate - this will create the CA automatically
    let hosts = vec!["test.local".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false, // RSA (default)
        false,
    )
    .unwrap();

    // Check CA key size using openssl
    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["rsa", "-noout", "-text"])
        .arg("-in")
        .arg(ca_path.join("rootCA-key.pem"))
        .output()
        .unwrap();

    let key_text = String::from_utf8_lossy(&output.stdout);
    println!("CA Key info: {}", key_text);

    assert!(
        key_text.contains("Private-Key: (3072 bit"),
        "CA should use RSA-3072, got: {}",
        key_text
    );

    // Clean up
    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_certificate_uses_rsa_2048_by_default() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    // Set CAROOT to use our temp directory
    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    let hosts = vec!["test.local".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false, // RSA (default)
        false,
    )
    .unwrap();

    // Check certificate key size using openssl
    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["rsa", "-noout", "-text"])
        .arg("-in")
        .arg(&key_file)
        .output()
        .unwrap();

    let key_text = String::from_utf8_lossy(&output.stdout);
    println!("Certificate Key info: {}", key_text);

    assert!(
        key_text.contains("Private-Key: (2048 bit"),
        "Certificate should use RSA-2048 by default, got: {}",
        key_text
    );

    // Clean up
    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_certificate_uses_ecdsa_p256_with_flag() {
    let _lock = get_test_lock();

    let temp_dir = TempDir::new().unwrap();
    let ca_path = temp_dir.path().to_path_buf();

    // Set CAROOT to use our temp directory
    unsafe {
        env::set_var("CAROOT", ca_path.to_str().unwrap());
    }

    let hosts = vec!["test.local".to_string()];
    let cert_file = temp_dir.path().join("test.pem");
    let key_file = temp_dir.path().join("test-key.pem");

    fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        true, // ECDSA
        false,
    )
    .unwrap();

    // Check certificate key type using openssl
    use std::process::Command;
    let output = Command::new("openssl")
        .args(&["ec", "-noout", "-text"])
        .arg("-in")
        .arg(&key_file)
        .output()
        .unwrap();

    let key_text = String::from_utf8_lossy(&output.stdout);
    println!("ECDSA Certificate Key info: {}", key_text);

    assert!(
        key_text.contains("ASN1 OID: prime256v1") || key_text.contains("NIST CURVE: P-256"),
        "Certificate should use ECDSA P-256 with --ecdsa flag, got: {}",
        key_text
    );

    // Clean up
    unsafe {
        env::remove_var("CAROOT");
    }
}
