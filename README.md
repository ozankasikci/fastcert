# rscert

A Rust implementation of mkcert - a simple zero-config tool for making locally-trusted development certificates.

## Overview

rscert is a command-line tool that makes it easy to create and manage locally-trusted development certificates. It works by creating a local certificate authority (CA) and then generating certificates signed by that CA. The CA certificate is installed in your system's trust store, making all certificates it signs trusted by your browsers and development tools.

## Features

- Zero configuration required - works out of the box
- Automatically creates and manages a local CA
- Generates certificates for multiple domains and IP addresses
- Supports wildcard certificates
- ECDSA and RSA key support
- Client certificate generation
- PKCS#12 format support
- Cross-platform support (macOS, Linux, Windows)
- Integrates with system trust stores
- Firefox and Java trust store support

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
git clone https://github.com/yourusername/rscert.git
cd rscert
cargo build --release
```

## Quick Start

```bash
# Install local CA in system trust store
rscert -install

# Generate certificate for a domain
rscert example.com

# Generate certificate for multiple domains and IPs
rscert example.com localhost 127.0.0.1 ::1

# Generate wildcard certificate
rscert "*.example.com"
```

## Platform Support

- macOS 10.12+
- Linux (with certutil for Firefox/Chrome, or manual installation)
- Windows 7+ (with administrator privileges for system-wide installation)

## How It Works

When you run `rscert -install`, it creates a new local certificate authority and installs it in your system trust store. When you generate certificates, they are signed by this local CA, making them trusted by your system.

The CA certificate and key are stored in:
- macOS/Linux: `$HOME/.local/share/rscert`
- Windows: `%LOCALAPPDATA%\rscert`

You can override this location by setting the `CAROOT` environment variable.

## Security

The CA key is the most sensitive file. Keep it secure and never share it. If you suspect it has been compromised, you should uninstall the CA and delete the CAROOT directory.

## License

MIT License - see LICENSE file for details

## Status

Active development - core functionality implemented
