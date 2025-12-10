# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-12-10

### Added
- Comprehensive code documentation across all modules
- Module-level documentation with examples
- Function documentation with detailed parameters and return values
- Improved error documentation
- Release profile optimizations for smaller, faster binaries
- Continuous Integration workflow
- Build status badges

### Changed
- Applied all clippy suggestions for better code quality
- Formatted code with rustfmt for consistency
- Optimized imports across all modules
- Enhanced README with comprehensive examples
- Updated documentation standards

### Fixed
- Manual strip patterns replaced with strip_prefix
- Removed unused code (dead code warnings)
- Improved code maintainability

## [0.1.0] - 2024-12-10

### Added
- Initial release
- Certificate Authority (CA) creation and management
- Certificate generation for domains and IP addresses
- Wildcard certificate support
- Multiple domain support (SAN certificates)
- ECDSA and RSA key support
- Client certificate generation
- PKCS#12 format support
- Certificate Signing Request (CSR) support
- Custom output file paths
- System trust store integration
  - macOS Keychain
  - Windows Certificate Store
  - Linux CA certificates
- Firefox/Chrome trust store support (NSS)
- Java KeyStore support
- Cross-platform support (macOS, Linux, Windows)
- Verbose and debug output modes
- Quiet mode for scripts
- Environment variable support (CAROOT, TRUST_STORES)
- Automatic IDNA encoding for internationalized domain names
- File permission management
- Comprehensive error handling

### Command-Line Interface
- `-install` - Install local CA in system trust stores
- `-uninstall` - Remove local CA from system trust stores
- `-CAROOT` - Display CA storage location
- `--cert-file` - Custom certificate output path
- `--key-file` - Custom key output path
- `--p12-file` - Custom PKCS#12 output path
- `--client` - Generate client authentication certificate
- `--ecdsa` - Use ECDSA instead of RSA
- `--pkcs12` - Generate PKCS#12 format
- `--csr` - Generate from CSR
- `--verbose` - Verbose output
- `--debug` - Debug output
- `--quiet` - Suppress output

### Platform-Specific Features

#### macOS
- Keychain integration via security-framework
- Automatic trust for system and user certificates
- Password prompt for CA installation

#### Linux
- System CA certificate installation
- NSS database support for Firefox/Chrome
- Java KeyStore integration

#### Windows
- Certificate Store integration
- Administrator privilege handling
- Wide character support

### Dependencies
- rcgen - Certificate generation
- ring - Cryptographic operations
- clap - Command-line parsing
- anyhow/thiserror - Error handling
- pem - PEM encoding/decoding
- p12 - PKCS#12 support
- x509-parser - Certificate parsing
- security-framework (macOS) - Keychain access
- windows (Windows) - Certificate Store access

### Documentation
- README with quick start guide
- Example usage in help text
- Inline code documentation
- Error messages with helpful hints

### Security
- Secure random number generation
- Proper file permissions (600 for private keys)
- Clear warnings about development-only use
- CA key protection recommendations

## [0.0.1] - 2024-12-09

### Added
- Initial project structure
- Basic Rust project setup
- License (MIT)
- Authors file
- Build configuration

---

## Release Notes

### Version 0.1.0

This is the first functional release of rscert, a Rust implementation of fastcert for creating locally-trusted development certificates.

**Highlights:**
- Full feature parity with fastcert for common use cases
- Cross-platform support (macOS, Linux, Windows)
- Easy installation and usage
- Comprehensive documentation

**Installation:**
```bash
cargo install --path .
```

**Quick Start:**
```bash
# Install CA
rscert -install

# Generate certificate
rscert example.com localhost 127.0.0.1
```

**Known Limitations:**
- Certificate validity is fixed at 825 days
- No support for custom certificate extensions
- No certificate revocation support

**Future Plans:**
- Custom validity periods
- Additional certificate extensions
- Performance optimizations
- Binary releases for all platforms

---

[Unreleased]: https://github.com/yourusername/rscert/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/rscert/releases/tag/v0.1.0
[0.0.1]: https://github.com/yourusername/rscert/releases/tag/v0.0.1
