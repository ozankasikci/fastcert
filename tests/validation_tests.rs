//! Comprehensive validation tests

mod common;

use common::get_test_lock;
use std::env;
use std::net::IpAddr;
use tempfile::TempDir;

#[test]
fn test_validate_ip_v4() {
    let _lock = get_test_lock();

    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    let result = fastcert::cert::validate_ip_address(&ip);
    assert!(result.is_ok(), "Should accept valid IPv4");
}

#[test]
fn test_validate_ip_v6() {
    let _lock = get_test_lock();

    let ip: IpAddr = "::1".parse().unwrap();
    let result = fastcert::cert::validate_ip_address(&ip);
    assert!(result.is_ok(), "Should accept valid IPv6");
}

#[test]
fn test_validate_ip_v6_full() {
    let _lock = get_test_lock();

    let ip: IpAddr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
    let result = fastcert::cert::validate_ip_address(&ip);
    assert!(result.is_ok(), "Should accept full IPv6");
}

#[test]
fn test_validate_email_valid() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_email_address("user@example.com");
    assert!(result.is_ok(), "Should accept valid email");
}

#[test]
fn test_validate_email_with_plus() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_email_address("user+tag@example.com");
    assert!(result.is_ok(), "Should accept email with plus");
}

#[test]
fn test_validate_email_subdomain() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_email_address("user@sub.example.com");
    assert!(result.is_ok(), "Should accept email with subdomain");
}

#[test]
fn test_validate_uri_https() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_uri("https://example.com");
    assert!(result.is_ok(), "Should accept HTTPS URI");
}

#[test]
fn test_validate_uri_http() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_uri("http://example.com");
    assert!(result.is_ok(), "Should accept HTTP URI");
}

#[test]
fn test_validate_uri_with_path() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_uri("https://example.com/path/to/resource");
    assert!(result.is_ok(), "Should accept URI with path");
}

#[test]
fn test_validate_uri_with_query() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_uri("https://example.com?query=value");
    assert!(result.is_ok(), "Should accept URI with query");
}

#[test]
fn test_validate_uri_with_port() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_uri("https://example.com:8443");
    assert!(result.is_ok(), "Should accept URI with port");
}

#[test]
fn test_validate_hostname_simple() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_hostname("example");
    assert!(result.is_ok(), "Should accept simple hostname");
}

#[test]
fn test_validate_hostname_fqdn() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_hostname("example.com");
    assert!(result.is_ok(), "Should accept FQDN");
}

#[test]
fn test_validate_hostname_subdomain() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_hostname("sub.example.com");
    assert!(result.is_ok(), "Should accept subdomain");
}

#[test]
fn test_validate_hostname_with_hyphen() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_hostname("my-domain.com");
    assert!(result.is_ok(), "Should accept hostname with hyphen");
}

#[test]
fn test_validate_hostname_with_numbers() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_hostname("example123.com");
    assert!(result.is_ok(), "Should accept hostname with numbers");
}

#[test]
fn test_validate_wildcard_basic() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_wildcard_depth("*.example.com");
    assert!(result.is_ok(), "Should accept single wildcard");
}

#[test]
fn test_validate_wildcard_subdomain() {
    let _lock = get_test_lock();

    let result = fastcert::cert::validate_wildcard_depth("*.sub.example.com");
    assert!(result.is_ok(), "Should accept wildcard with subdomain");
}

#[test]
fn test_build_san_list_single_domain() {
    let _lock = get_test_lock();

    let hosts = vec!["example.com".to_string()];
    let result = fastcert::cert::build_san_list(&hosts);
    assert!(result.is_ok(), "Should build SAN list for single domain");
    assert_eq!(result.unwrap().len(), 1, "Should have 1 SAN");
}

#[test]
fn test_build_san_list_multiple() {
    let _lock = get_test_lock();

    let hosts = vec![
        "example.com".to_string(),
        "192.168.1.1".to_string(),
        "user@example.com".to_string(),
    ];
    let result = fastcert::cert::build_san_list(&hosts);
    assert!(result.is_ok(), "Should build SAN list for mixed types");
    assert_eq!(result.unwrap().len(), 3, "Should have 3 SANs");
}

#[test]
fn test_build_san_list_ipv6() {
    let _lock = get_test_lock();

    let hosts = vec!["::1".to_string(), "2001:db8::1".to_string()];
    let result = fastcert::cert::build_san_list(&hosts);
    assert!(result.is_ok(), "Should build SAN list for IPv6");
    assert_eq!(result.unwrap().len(), 2, "Should have 2 IPv6 SANs");
}

#[test]
fn test_create_cert_params() {
    let _lock = get_test_lock();

    let hosts = vec!["example.com".to_string()];
    let result = fastcert::cert::create_cert_params(&hosts);
    assert!(result.is_ok(), "Should create cert params");
}

#[test]
fn test_create_cert_params_multiple() {
    let _lock = get_test_lock();

    let hosts = vec![
        "example.com".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let result = fastcert::cert::create_cert_params(&hosts);
    assert!(result.is_ok(), "Should create cert params for multiple hosts");
}

#[test]
fn test_format_expiration_date() {
    let _lock = get_test_lock();

    use time::OffsetDateTime;

    let expiration = OffsetDateTime::now_utc() + time::Duration::days(825);
    let formatted = fastcert::cert::format_expiration_date(expiration);

    assert!(!formatted.is_empty(), "Should format expiration date");
}

#[test]
fn test_cert_to_pem() {
    let _lock = get_test_lock();

    let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // Simplified DER
    let pem = fastcert::cert::cert_to_pem(&cert_der);

    assert!(pem.contains("BEGIN CERTIFICATE"), "Should have PEM header");
    assert!(pem.contains("END CERTIFICATE"), "Should have PEM footer");
}

#[test]
fn test_domain_to_unicode_ascii() {
    let _lock = get_test_lock();

    let result = fastcert::cert::domain_to_unicode("example.com");
    assert_eq!(result, "example.com", "ASCII should pass through");
}

#[test]
fn test_cert_chain_validation() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    // Generate a certificate
    let hosts = vec!["chain-test.local".to_string()];
    let cert_file = temp_dir.path().join("chain.pem");
    let key_file = temp_dir.path().join("chain-key.pem");

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

    // Read cert and CA
    let cert_pem = std::fs::read_to_string(&cert_file).unwrap();
    let ca_pem = std::fs::read_to_string(temp_dir.path().join("rootCA.pem")).unwrap();

    // Parse to DER
    let cert_parsed = pem::parse(&cert_pem).unwrap();
    let ca_parsed = pem::parse(&ca_pem).unwrap();

    // Validate chain
    let result =
        fastcert::cert::validate_cert_chain(cert_parsed.contents(), ca_parsed.contents());
    assert!(result.is_ok(), "Certificate chain should be valid");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_generate_file_names_single() {
    let _lock = get_test_lock();

    use fastcert::cert::CertificateConfig;

    let config = CertificateConfig {
        hosts: vec!["example.com".to_string()],
        cert_file: None,
        key_file: None,
        p12_file: None,
        client_cert: false,
        use_ecdsa: false,
        pkcs12: false,
    };

    let (cert, _key, _) = fastcert::cert::generate_file_names(&config);
    assert!(
        cert.to_str().unwrap().contains("example.com"),
        "Cert file should contain domain"
    );
}

#[test]
fn test_generate_file_names_multiple() {
    let _lock = get_test_lock();

    use fastcert::cert::CertificateConfig;

    let config = CertificateConfig {
        hosts: vec![
            "example.com".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ],
        cert_file: None,
        key_file: None,
        p12_file: None,
        client_cert: false,
        use_ecdsa: false,
        pkcs12: false,
    };

    let (cert, _key, _) = fastcert::cert::generate_file_names(&config);
    assert!(
        cert.to_str().unwrap().contains("+"),
        "Cert file should indicate multiple hosts"
    );
}

#[test]
fn test_generate_file_names_wildcard() {
    let _lock = get_test_lock();

    use fastcert::cert::CertificateConfig;

    let config = CertificateConfig {
        hosts: vec!["*.example.com".to_string()],
        cert_file: None,
        key_file: None,
        p12_file: None,
        client_cert: false,
        use_ecdsa: false,
        pkcs12: false,
    };

    let (cert, _, _) = fastcert::cert::generate_file_names(&config);
    assert!(
        cert.to_str().unwrap().contains("_wildcard"),
        "Cert file should indicate wildcard"
    );
}

#[test]
fn test_certificate_with_client_auth() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["client@example.com".to_string()];
    let cert_file = temp_dir.path().join("client-auth.pem");
    let key_file = temp_dir.path().join("client-auth-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        true, // client cert
        false,
        false,
    );
    assert!(result.is_ok(), "Should generate client cert");

    unsafe {
        env::remove_var("CAROOT");
    }
}

#[test]
fn test_certificate_with_ecdsa() {
    let _lock = get_test_lock();
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        env::set_var("CAROOT", temp_dir.path().to_str().unwrap());
    }

    let hosts = vec!["ecdsa.local".to_string()];
    let cert_file = temp_dir.path().join("ecdsa-cert.pem");
    let key_file = temp_dir.path().join("ecdsa-key.pem");

    let result = fastcert::cert::generate_certificate(
        &hosts,
        Some(cert_file.to_str().unwrap()),
        Some(key_file.to_str().unwrap()),
        None,
        false,
        true, // ecdsa
        false,
    );
    assert!(result.is_ok(), "Should generate ECDSA cert");

    unsafe {
        env::remove_var("CAROOT");
    }
}
