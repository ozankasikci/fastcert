# rscert

A Rust implementation of mkcert - a simple tool for making locally-trusted development certificates.

## Features

- Creates locally-trusted development certificates
- No configuration required
- Supports multiple platforms (macOS, Linux, Windows)

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Install local CA
rscert -install

# Generate certificate
rscert example.com localhost 127.0.0.1
```

## Status

🚧 Work in progress - implementing core functionality
