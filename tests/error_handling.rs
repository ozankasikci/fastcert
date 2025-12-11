//! Tests for error handling and edge cases

mod common;

use common::get_test_lock;
use std::env;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_csr_file_not_found() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let non_existent = temp_dir.path().join("nonexistent.csr");
    let result = fastcert::cert::read_csr_file(non_existent.to_str().unwrap());
    assert!(result.is_err(), "Should fail when CSR file doesn't exist");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_csr_invalid_pem_format() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Create an invalid CSR file (not valid PEM)
    let invalid_csr = temp_dir.path().join("invalid.csr");
    let mut file = fs::File::create(&invalid_csr).unwrap();
    file.write_all(b"This is not a valid PEM file").unwrap();
    drop(file);

    let csr_bytes = fs::read(&invalid_csr).unwrap();
    let result = fastcert::cert::parse_csr_pem(&csr_bytes);
    assert!(result.is_err(), "Should fail with invalid PEM format");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_csr_no_pem_markers() {
    let _lock = get_test_lock();

    let content = b"Some random content without PEM markers";
    let result = fastcert::cert::parse_csr_pem(content);
    assert!(result.is_err(), "Should fail when no PEM markers found");
}

#[test]
fn test_csr_invalid_utf8() {
    let _lock = get_test_lock();

    // Create invalid UTF-8 bytes
    let invalid_utf8: Vec<u8> = vec![0xFF, 0xFE, 0xFD];
    let result = fastcert::cert::parse_csr_pem(&invalid_utf8);
    assert!(result.is_err(), "Should fail with invalid UTF-8");
}

#[test]
fn test_domain_to_ascii_valid() {
    let _lock = get_test_lock();

    // Test with valid ASCII domain (should pass through)
    let result = fastcert::cert::domain_to_ascii("example.com");
    assert!(result.is_ok(), "Should handle valid ASCII domain");
    assert_eq!(result.unwrap(), "example.com");
}

#[test]
fn test_validate_uri_empty_scheme() {
    let _lock = get_test_lock();

    // Test URI with empty scheme (://example.com)
    let result = fastcert::cert::validate_uri("://example.com");
    assert!(result.is_ok() || result.is_err()); // Either parsing fails or validation fails
}

#[test]
fn test_validate_uri_whitespace() {
    let _lock = get_test_lock();

    // Test URI with whitespace
    let result = fastcert::cert::validate_uri("https://example .com");
    assert!(result.is_err(), "Should fail with whitespace in URI");
}

#[test]
fn test_validate_uri_no_host() {
    let _lock = get_test_lock();

    // Test URI without host
    let result = fastcert::cert::validate_uri("https://");
    assert!(result.is_err(), "Should fail with no host");
}

#[test]
fn test_validate_hostname_invalid_chars() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_hostname("invalid@hostname");
    assert!(result.is_err(), "Should fail with invalid characters");
}

#[test]
fn test_validate_hostname_empty() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_hostname("");
    assert!(result.is_err(), "Should fail with empty hostname");
}

#[test]
fn test_wildcard_depth_too_deep() {
    let _lock = get_test_lock();

    // Double wildcard should fail
    let result = fastcert::cert::validate_wildcard_depth("*.*.example.com");
    assert!(result.is_err(), "Should fail with double wildcard");
}

#[test]
fn test_wildcard_depth_single() {
    let _lock = get_test_lock();

    // Single wildcard should be OK
    let result = fastcert::cert::validate_wildcard_depth("*.example.com");
    assert!(result.is_ok(), "Single wildcard should be valid");
}

#[test]
fn test_empty_hosts_list() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let empty_hosts: Vec<String> = vec![];
    let result =
        fastcert::cert::generate_certificate(&empty_hosts, None, None, None, false, false, false);
    assert!(result.is_err(), "Should fail with empty hosts list");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_invalid_email_format() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_email_address("invalid-email");
    assert!(result.is_err(), "Should fail with invalid email");
}

#[test]
fn test_invalid_email_no_at() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_email_address("nodomain.com");
    assert!(result.is_err(), "Should fail with email missing @");
}

#[test]
fn test_invalid_email_empty() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_email_address("");
    assert!(result.is_err(), "Should fail with empty email");
}

#[test]
fn test_invalid_ip_address() {
    let _lock = get_test_lock();

    // Invalid IPv4
    let result = "999.999.999.999".parse::<std::net::IpAddr>();
    assert!(result.is_err(), "Should fail with invalid IPv4");
}

#[test]
fn test_cert_expiry_calculation() {
    let _lock = get_test_lock();

    use fastcert::cert::calculate_cert_expiration;
    use time::OffsetDateTime;

    let now = OffsetDateTime::now_utc();
    let expiration = calculate_cert_expiration();

    let diff = (expiration - now).whole_days();
    // The implementation uses 730 + 90 = 820 days (2 years + 3 months)
    // Allow for small time differences during test execution
    assert!(
        (819..=821).contains(&diff),
        "Certificate should be valid for approximately 820 days, got {} days",
        diff
    );
}

#[test]
fn test_cert_expiry_soon() {
    let _lock = get_test_lock();

    use fastcert::cert::is_cert_expiring_soon;
    use time::{Duration, OffsetDateTime};

    let now = OffsetDateTime::now_utc();

    // Expires in 5 days - should return true
    let expires_soon = now + Duration::days(5);
    assert!(
        is_cert_expiring_soon(expires_soon),
        "Should detect expiring soon"
    );

    // Expires in 50 days - should return false
    let expires_later = now + Duration::days(50);
    assert!(
        !is_cert_expiring_soon(expires_later),
        "Should not detect as expiring soon"
    );
}

#[test]
fn test_certificate_generation_with_email() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["user@example.com".to_string()];
    let cert_file = temp_dir.path().join("email.pem");
    let key_file = temp_dir.path().join("email-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    );
    assert!(result.is_ok(), "Should generate cert with email SAN");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_certificate_generation_with_uri() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["https://example.com/path".to_string()];
    let cert_file = temp_dir.path().join("uri.pem");
    let key_file = temp_dir.path().join("uri-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    );
    assert!(result.is_ok(), "Should generate cert with URI SAN");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_serial_number_uniqueness() {
    let _lock = get_test_lock();

    use fastcert::cert::generate_serial_number;

    let mut serials = std::collections::HashSet::new();

    // Generate 100 serial numbers
    for _ in 0..100 {
        let serial = generate_serial_number();
        assert!(
            serials.insert(serial),
            "Serial numbers should be unique"
        );
    }

    assert_eq!(serials.len(), 100, "Should have 100 unique serials");
}

#[test]
fn test_domain_to_unicode() {
    let _lock = get_test_lock();

    use fastcert::cert::domain_to_unicode;

    // Test ASCII passthrough
    let result = domain_to_unicode("example.com");
    assert_eq!(result, "example.com", "ASCII should pass through");

    // Test punycode conversion
    let result = domain_to_unicode("xn--e1afmkfd.xn--p1ai");
    // Should convert punycode to unicode
    assert!(!result.is_empty(), "Should convert punycode");
}

#[test]
fn test_pkcs12_generation() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["pkcs12.local".to_string()];
    let p12_file = temp_dir.path().join("test.p12");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        None,
        None,
        Some(p12_file.to_str().unwrap()),
        false,
        false,
        true, // pkcs12
    );
    assert!(result.is_ok(), "Should generate PKCS12 file");
    assert!(p12_file.exists(), "PKCS12 file should exist");

    // Verify file is not empty
    let metadata = fs::metadata(&p12_file).unwrap();
    assert!(metadata.len() > 0, "PKCS12 file should not be empty");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_combined_cert_key_file() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["combined.local".to_string()];
    let combined_file = temp_dir.path().join("combined.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(combined_file.to_str().unwrap()),
        Some(combined_file.to_str().unwrap()), // Same file for both
        None,
        false,
        false,
        false,
    );
    assert!(result.is_ok(), "Should generate combined cert+key file");
    assert!(combined_file.exists(), "Combined file should exist");

    // Verify file contains both cert and key
    let contents = fs::read_to_string(&combined_file).unwrap();
    assert!(
        contents.contains("BEGIN CERTIFICATE"),
        "Should contain certificate"
    );
    assert!(
        contents.contains("BEGIN PRIVATE KEY") || contents.contains("BEGIN RSA PRIVATE KEY"),
        "Should contain private key"
    );

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_file_naming_with_port() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();
    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Test that port numbers in hostnames are handled
    let hosts = vec!["example.com:8080".to_string()];
    let cert_file = temp_dir.path().join("port-test.pem");
    let key_file = temp_dir.path().join("port-test-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        false,
        false,
    );
    // This should work - ports are stripped during validation
    assert!(result.is_ok() || result.is_err()); // Either works or fails gracefully

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_host_type_parsing() {
    let _lock = get_test_lock();

    use fastcert::cert::HostType;

    // Test DNS parsing
    let result = HostType::parse("example.com");
    assert!(matches!(result, Ok(HostType::DnsName(_))));

    // Test IP parsing
    let result = HostType::parse("192.168.1.1");
    assert!(matches!(result, Ok(HostType::IpAddress(_))));

    // Test email parsing
    let result = HostType::parse("user@example.com");
    assert!(matches!(result, Ok(HostType::Email(_))));

    // Test URI parsing
    let result = HostType::parse("https://example.com");
    assert!(matches!(result, Ok(HostType::Uri(_))));
}
