# Contributing to fastcert

Thank you for considering contributing to fastcert! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Exact steps to reproduce the problem
- Expected behavior vs actual behavior
- Your environment (OS, Rust version, fastcert version)
- Any relevant error messages or logs

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- A clear and descriptive title
- Detailed description of the proposed functionality
- Explain why this enhancement would be useful
- List any similar features in other tools

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature or fix
3. Make your changes
4. Add tests for your changes
5. Ensure all tests pass
6. Update documentation if needed
7. Submit a pull request

## Development Setup

### Prerequisites

- Rust 1.70 or later
- Cargo
- Git

### Building from Source

```bash
git clone https://github.com/yourusername/fastcert.git
cd fastcert
cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Code Style

This project uses standard Rust formatting:

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run clippy for lints
cargo clippy

# Fix clippy suggestions
cargo clippy --fix
```

### Commit Messages

- Use clear and descriptive commit messages
- Start with a verb in present tense (e.g., "add", "fix", "update")
- Keep the first line under 72 characters
- Reference issues and pull requests when relevant

Good examples:
- "add support for custom validity periods"
- "fix certificate generation for wildcard domains"
- "update README with installation instructions"

Avoid:
- "fixed stuff"
- "updates"
- "WIP"

## Project Structure

```
fastcert/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library exports
│   ├── ca.rs            # CA management
│   ├── cert.rs          # Certificate generation
│   ├── error.rs         # Error types
│   ├── fileutil.rs      # File utilities
│   └── truststore/      # Trust store integrations
│       ├── mod.rs
│       ├── macos.rs
│       ├── linux.rs
│       ├── windows.rs
│       ├── nss.rs
│       └── java.rs
├── tests/               # Integration tests
├── Cargo.toml          # Dependencies
└── README.md           # Documentation
```

## Testing

### Unit Tests

Add unit tests in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        // Your test here
    }
}
```

### Integration Tests

Add integration tests in the `tests/` directory:

```rust
use fastcert;

#[test]
fn test_full_workflow() {
    // Your integration test here
}
```

### Platform-Specific Testing

Some features are platform-specific. Use conditional compilation:

```rust
#[cfg(target_os = "macos")]
#[test]
fn test_macos_feature() {
    // macOS-specific test
}
```

## Documentation

- Add doc comments to all public APIs
- Update README.md for user-facing changes
- Include examples in doc comments
- Keep documentation clear and concise

Example:

```rust
/// Generates a new certificate for the specified domains.
///
/// # Arguments
///
/// * `domains` - A list of domain names or IP addresses
/// * `ecdsa` - Whether to use ECDSA instead of RSA
///
/// # Examples
///
/// ```
/// use fastcert::cert::generate_certificate;
///
/// generate_certificate(&["example.com"], None, None, None, false, false, false)?;
/// ```
pub fn generate_certificate(domains: &[String], ...) -> Result<()> {
    // Implementation
}
```

## Release Process

1. Update version in Cargo.toml
2. Update CHANGELOG.md
3. Create a git tag
4. Push tag to trigger release

## Platform Support

When adding features, consider:

- macOS compatibility
- Linux compatibility (multiple distros)
- Windows compatibility
- Graceful degradation when features aren't available

## Getting Help

- Open an issue for questions
- Check existing issues and pull requests
- Review the README and documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
