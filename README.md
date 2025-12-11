# fastcert

[![Crates.io](https://img.shields.io/crates/v/fastcert.svg)](https://crates.io/crates/fastcert)
[![Homebrew](https://img.shields.io/badge/homebrew-ozankasikci%2Ftap-orange.svg)](https://github.com/ozankasikci/homebrew-tap)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-93%20passing-brightgreen.svg)](#testing)
[![Coverage](assets/coverage.svg)](#testing)

A simple zero-config tool for making locally-trusted development certificates.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
  - [Homebrew](#homebrew)
  - [Cargo](#cargo)
  - [From Source](#from-source)
  - [Prerequisites](#prerequisites)
  - [Platform-Specific Requirements](#platform-specific-requirements)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Platform Support](#platform-support)
- [Advanced Options](#advanced-options)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Security](#security)
- [License](#license)

## Overview

fastcert is a command-line tool that makes it easy to create and manage locally-trusted development certificates. It works by creating a local certificate authority (CA) and then generating certificates signed by that CA. The CA certificate is installed in your system's trust store, making all certificates it signs trusted by your browsers and development tools.

## Features

- Zero configuration required - works out of the box
- Automatically creates and manages a local CA
- Generates certificates for multiple domains and IP addresses
- Supports wildcard certificates
- RSA key support (default, maximum compatibility)
- ECDSA key support (optional, better performance)
- Client certificate generation
- PKCS#12 format support
- Cross-platform support (macOS, Linux, Windows)
- Integrates with system trust stores
- Firefox and Java trust store support
- Certificates properly signed by CA (not self-signed)
- Comprehensive test coverage (85+ tests)

## Installation

### Homebrew

```bash
brew install ozankasikci/tap/fastcert
```

### Cargo

```bash
cargo install fastcert
```

### From Source

1. Clone the repository:
```bash
git clone https://github.com/ozankasikci/fastcert
cd fastcert
```

2. Build and install:
```bash
cargo install --path .
```

This will install the `fastcert` binary to your cargo bin directory (usually `~/.cargo/bin`).

For development or custom builds:

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# The binary will be in target/release/fastcert
```

### Prerequisites

- Rust 1.70 or later
- Cargo package manager
- Administrator/root privileges for installing CA certificates

### Platform-Specific Requirements

**macOS:**
- No additional dependencies required
- System trust store integration works out of the box

**Linux:**
- For Firefox/Chrome support: `certutil` (NSS tools)
  ```bash
  # Debian/Ubuntu
  sudo apt install libnss3-tools

  # Fedora/RHEL
  sudo dnf install nss-tools

  # Arch Linux
  sudo pacman -S nss
  ```

**Windows:**
- Administrator privileges required for system trust store installation
- No additional dependencies needed

## Quick Start

```bash
# Install local CA in system trust store
fastcert --install

# Generate certificate for a domain (RSA is the default)
fastcert example.com

# Generate certificate for multiple domains and IPs
fastcert example.com localhost 127.0.0.1 ::1

# Generate wildcard certificate
fastcert "*.example.com"

# Generate certificate with ECDSA keys (optional)
fastcert --ecdsa example.com
```

**Note:** RSA-2048 is the default key type. Use `--ecdsa` for ECDSA P-256 keys if needed.

## Usage Examples

### Basic Certificate Generation

Generate a certificate for a single domain:
```bash
fastcert example.com
```

This creates two files:
- `example.com.pem` - the certificate (signed by the CA)
- `example.com-key.pem` - the private key (RSA-2048)

### Multiple Domains

Generate a certificate valid for multiple domains and IP addresses:
```bash
fastcert example.com localhost 127.0.0.1 ::1
```

The files will be named `example.com+3.pem` and `example.com+3-key.pem` (the +3 indicates 3 additional names beyond the first).

**Note:** Always include `localhost` and `127.0.0.1` if you want to access your service via localhost.

### Wildcard Certificates

Generate a wildcard certificate:
```bash
fastcert "*.example.com"
```

Creates `_wildcard.example.com.pem` and `_wildcard.example.com-key.pem`.

### Custom File Names

Specify custom output file names:
```bash
fastcert --cert-file mycert.pem --key-file mykey.pem example.com
```

### ECDSA Keys (Optional)

Generate a certificate with ECDSA keys instead of RSA:
```bash
fastcert --ecdsa example.com
```

ECDSA P-256 keys provide equivalent security to RSA-2048 with smaller key sizes, resulting in:
- Smaller certificates
- Faster cryptographic operations
- Better performance

Both RSA and ECDSA are fully supported.

### Client Certificates

Generate a certificate for client authentication:
```bash
fastcert --client client.example.com
```

### PKCS12 Format

Generate a PKCS12 file (.pfx) containing both certificate and key:
```bash
fastcert --pkcs12 example.com
```

Or specify a custom PKCS12 file path:
```bash
fastcert --p12-file mycert.pfx example.com
```

### Certificate Signing Requests

Generate a certificate from an existing CSR:
```bash
fastcert --csr mycsr.pem --cert-file mycert.pem
```

### Managing the CA

View the CA certificate location:
```bash
fastcert --CAROOT
```

Install the CA in system trust stores:
```bash
fastcert --install
```

Uninstall the CA from system trust stores (but keep the certificate):
```bash
fastcert --uninstall
```

### Environment Variables

Set a custom CA location:
```bash
export CAROOT="$HOME/my-ca"
fastcert --install
```

Specify which trust stores to use:
```bash
export TRUST_STORES="system,firefox,java"
fastcert --install
```

## Platform Support

- macOS 10.12+
- Linux (with certutil for Firefox/Chrome, or manual installation)
- Windows 7+ (with administrator privileges for system-wide installation)

## Advanced Options

### Command-Line Flags

**Certificate Generation:**
- `--cert-file FILE` - Custom path for the certificate output file
- `--key-file FILE` - Custom path for the private key output file
- `--p12-file FILE` - Custom path for PKCS12 output file
- `--client` - Generate a certificate for client authentication
- `--ecdsa` - Use ECDSA P-256 keys instead of RSA-2048 (optional)
- `--pkcs12` - Generate PKCS12 format (.pfx) file
- `--csr FILE` - Generate certificate from an existing CSR

**CA Management:**
- `--install` - Install the local CA in system trust stores
- `--uninstall` - Remove the local CA from system trust stores
- `--CAROOT` - Print the CA certificate storage location

**Output Control:**
- `-v, --verbose` - Enable verbose output
- `--debug` - Enable debug output (implies verbose)
- `-q, --quiet` - Suppress all output except errors

### Environment Variables

**CAROOT:**
Set the directory where the CA certificate and key are stored. This allows you to maintain multiple independent CAs.

```bash
export CAROOT="$HOME/my-custom-ca"
fastcert --install
```

**TRUST_STORES:**
Comma-separated list of trust stores to use. By default, fastcert auto-detects available stores.

Options:
- `system` - Operating system trust store
- `nss` - Firefox and Chrome (via NSS)
- `java` - Java trust store

```bash
export TRUST_STORES="system,nss"
fastcert --install
```

**FASTCERT_VERBOSE:**
Enable verbose output (same as `--verbose`).

**FASTCERT_DEBUG:**
Enable debug output (same as `--debug`).

**FASTCERT_QUIET:**
Suppress output except errors (same as `--quiet`).

### Certificate Validity

All certificates generated by fastcert are valid for 825 days (approximately 2 years and 3 months), which is the maximum validity period accepted by major browsers.

### Key Types and Sizes

**RSA (default):**
- CA: RSA-3072
- Certificates: RSA-2048
- Standard and widely compatible
- Trusted by all systems

**ECDSA (optional --ecdsa flag):**
- Curve: P-256 (secp256r1)
- Key size: 256 bits (equivalent security to RSA-2048)
- Smaller certificates
- Faster operations
- Modern and efficient

Both key types are fully supported. Choose based on your needs:
- RSA: Maximum compatibility (default)
- ECDSA: Better performance and smaller certificates

## How It Works

When you run `fastcert --install`, it creates a new local certificate authority and installs it in your system trust store. When you generate certificates, they are signed by this local CA, making them trusted by your system.

The CA certificate and key are stored in:
- macOS/Linux: `$HOME/.local/share/fastcert`
- Windows: `%LOCALAPPDATA%\fastcert`

You can override this location by setting the `CAROOT` environment variable.

### Certificate Generation Process

1. Check if CA exists, create if needed (RSA-3072)
2. Parse and validate domain names/IP addresses
3. Generate a new private key (RSA-2048 by default, or ECDSA P-256 with --ecdsa)
4. Create certificate parameters with SANs
5. Sign the certificate with the CA key
6. Write certificate and key files to disk

### Trust Store Integration

fastcert automatically detects and integrates with:
- System trust store (macOS Keychain, Windows Certificate Store, Linux CA certificates)
- Firefox/Chrome (via NSS)
- Java KeyStore

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test integration
cargo test --test e2e
cargo test --test security

# Run with verbose output
cargo test -- --nocapture

# Generate code coverage report
cargo install cargo-tarpaulin
cargo tarpaulin --out Html --output-dir coverage
```

## Troubleshooting

### Certificate Not Trusted

**Problem:** Browser shows "Not Secure" or certificate warning.

**Solutions:**
1. Make sure you ran `fastcert --install` before generating certificates
2. Restart your browser **completely** (quit and reopen) after installing the CA
3. Verify the certificate includes the domain you're accessing:
   - Include `localhost 127.0.0.1` if accessing via localhost
   - Example: `fastcert myapp.dev localhost 127.0.0.1 ::1`
4. On Linux, you may need to manually trust the CA certificate
5. Verify the certificate is signed by the CA:
   ```bash
   openssl verify -CAfile "$(fastcert --CAROOT)/rootCA.pem" yourcert.pem
   ```

### Permission Denied

**Problem:** Error installing CA certificate.

**Solutions:**
- macOS: The system will prompt for your password
- Linux: Run with `sudo` if installing system-wide
- Windows: Run as Administrator

### Firefox Not Trusting Certificates

**Problem:** Firefox shows certificate error even though system trusts it.

**Solutions:**
1. Install NSS tools (certutil):
   ```bash
   # Debian/Ubuntu
   sudo apt install libnss3-tools

   # macOS
   brew install nss
   ```
2. Run `fastcert --install` again
3. Restart Firefox

### Java Applications Not Trusting Certificates

**Problem:** Java applications reject certificates.

**Solutions:**
1. Make sure Java is installed
2. Run `fastcert --install` to add CA to Java trust store
3. Restart Java applications

### CA Already Exists

**Problem:** Want to recreate the CA.

**Solution:**
```bash
# Uninstall from trust stores
fastcert --uninstall

# Find CA location
fastcert --CAROOT

# Delete the CA directory
rm -rf $(fastcert --CAROOT)

# Reinstall
fastcert --install
```

### Wrong Domain in Certificate

**Problem:** Certificate generated for wrong domain.

**Solution:**
Delete the certificate files and regenerate:
```bash
rm example.com*.pem
fastcert example.com
```

### Multiple CAs

**Problem:** Need different CAs for different projects.

**Solution:**
Use the CAROOT environment variable:
```bash
# Project 1
export CAROOT="$HOME/ca-project1"
fastcert --install
fastcert project1.local

# Project 2
export CAROOT="$HOME/ca-project2"
fastcert --install
fastcert project2.local
```

### Certificate Expired

**Problem:** Certificate has expired.

**Solution:**
Certificates are valid for 825 days. Simply regenerate:
```bash
fastcert example.com
```

### Debugging Issues

Enable verbose or debug mode for detailed output:
```bash
fastcert --verbose example.com
fastcert --debug -install
```

## FAQ

### Is this secure for production use?

**No.** fastcert is designed for development and testing only. Never use these certificates in production environments. The CA key is stored locally without additional protection, making it unsuitable for production use.

### Can I use this for internal services?

While technically possible, it's not recommended. For internal services, consider using a proper internal PKI solution. fastcert is best suited for local development.

### Why does my browser still show a warning?

Make sure:
1. You ran `fastcert --install` before generating certificates
2. The certificate includes the exact domain/IP you're accessing
3. You've restarted your browser after installation
4. The certificate hasn't expired

### Can I trust certificates on another machine?

Yes, but it's not recommended. You would need to copy the CA certificate to the other machine and install it manually. This defeats the purpose of a local CA and creates security risks.

### What happens if I lose my CA key?

If you lose the CA key, you cannot generate new trusted certificates. You'll need to:
1. Run `fastcert --uninstall` on all machines that trust the old CA
2. Delete the CAROOT directory
3. Run `fastcert --install` to create a new CA
4. Regenerate all certificates

### How long are certificates valid?

Certificates are valid for 825 days from creation. This is the maximum validity period accepted by major browsers and operating systems.

### Can I use custom validity periods?

Currently, no. The validity period is fixed at 825 days to ensure browser compatibility.

### Does this work with Docker?

Yes. You can mount the CA certificate into Docker containers and configure them to trust it. However, it's usually easier to use the container's hostname and generate a certificate for it.

### Can I automate certificate generation?

Yes. fastcert is designed to be scriptable. Example:
```bash
#!/bin/bash
fastcert --install
for domain in app.local api.local db.local; do
    fastcert "$domain"
done
```

### Does this support IPv6?

Yes. You can generate certificates for IPv6 addresses:
```bash
fastcert ::1 2001:db8::1
```

### Can I revoke certificates?

No. Certificate revocation is not supported. If you need to invalidate a certificate, simply delete it and don't use it anymore.

## Security

The CA key is the most sensitive file. Keep it secure and never share it. If you suspect it has been compromised, you should uninstall the CA and delete the CAROOT directory.

**Best Practices:**
- Never commit CA certificates or keys to version control
- Don't share the CA key with others
- Use different CAs for different trust boundaries
- Regularly rotate certificates (regenerate every few months)
- Keep the CA key file permissions restricted (600)
- Only use for local development, never production

## Acknowledgments

This project was inspired by [mkcert](https://github.com/FiloSottile/mkcert).

## License

BSD 3-Clause License - see LICENSE file for details

## Status

Active development - core functionality implemented
