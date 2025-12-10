# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Context

**Important:** fastcert is designed for local development use only. It is **NOT** intended for production environments.

### What fastcert Does

- Creates a local Certificate Authority (CA) on your machine
- Generates SSL/TLS certificates signed by that local CA
- Installs the CA certificate in your system's trust store
- Provides certificates trusted by your local browsers and tools

### Security Considerations

1. **Local Development Only**: Never use fastcert for production services
2. **CA Key Storage**: The CA private key is stored unencrypted on your local filesystem
3. **Trust Scope**: Anyone with access to your CA key can create certificates trusted by your system
4. **No Revocation**: Certificate revocation is not supported

## Threat Model

### In Scope

- Vulnerabilities in certificate generation
- Issues with trust store integration
- File permission problems
- Dependency vulnerabilities

### Out of Scope

- Attack scenarios requiring physical access to your development machine
- Social engineering attacks
- Issues related to production use (which is explicitly not supported)

## Reporting a Vulnerability

If you discover a security vulnerability, please report it by emailing security@example.com (replace with actual contact).

**Please do NOT report security vulnerabilities through public GitHub issues.**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 30 days
  - Medium: Within 90 days
  - Low: Next release

## Security Best Practices

### For Users

1. **Protect Your CA Key**
   ```bash
   # Check CA location
   fastcert -CAROOT

   # Ensure proper permissions (Unix/macOS)
   chmod 600 $(fastcert -CAROOT)/rootCA-key.pem
   ```

2. **Don't Share Your CA**
   - Never commit CA certificates or keys to version control
   - Don't share your CA with other developers
   - Each developer should have their own CA

3. **Limit Trust Scope**
   - Only install the CA on machines you control
   - Uninstall when no longer needed:
     ```bash
     fastcert -uninstall
     rm -rf $(fastcert -CAROOT)
     ```

4. **Regular Rotation**
   - Periodically recreate your CA
   - Regenerate certificates regularly

5. **Monitor CA Usage**
   - Be aware of what certificates you've generated
   - Delete old/unused certificates

### For Developers

1. **Dependency Management**
   - Keep dependencies up to date
   - Review dependency security advisories
   - Use `cargo audit` regularly

2. **Secure Defaults**
   - File permissions should be restrictive by default
   - CA keys should never be world-readable
   - Temporary files should be cleaned up

3. **Input Validation**
   - Validate all domain names and IP addresses
   - Sanitize file paths
   - Prevent path traversal attacks

4. **Trust Store Integration**
   - Minimize required privileges
   - Provide clear warnings about trust implications
   - Support safe uninstall

## Known Limitations

### CA Key Storage

The CA private key is stored unencrypted in:
- macOS/Linux: `$HOME/.local/share/fastcert`
- Windows: `%LOCALAPPDATA%\fastcert`

This is intentional for ease of use in development. For production use, a proper PKI solution with HSM support should be used.

### No Password Protection

CA keys are not password-protected by default. This is a design choice for developer convenience. If you need password protection, use a proper CA solution.

### Trust Store Modification

Installing the CA requires modifying system trust stores:
- **macOS**: Requires your password
- **Linux**: May require root access
- **Windows**: Requires administrator privileges

This is necessary for the certificates to be trusted but increases the security impact of a compromised CA.

## Dependency Security

We use the following tools to monitor dependency security:

- `cargo audit` - Checks for known vulnerabilities
- Dependabot - Automated dependency updates
- GitHub Security Advisories

To check dependencies yourself:

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

## Incident Response

If the CA key is compromised:

1. **Immediately Uninstall**
   ```bash
   fastcert -uninstall
   ```

2. **Delete CA Files**
   ```bash
   rm -rf $(fastcert -CAROOT)
   ```

3. **Create New CA**
   ```bash
   fastcert -install
   ```

4. **Regenerate All Certificates**
   ```bash
   fastcert your-domains-here
   ```

5. **Review System**
   - Check for unauthorized certificates
   - Review system logs
   - Consider whether the system needs forensic analysis

## Contact

For security concerns, contact: security@example.com (replace with actual contact)

For general questions, use GitHub Issues.

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged in release notes unless they prefer to remain anonymous.
