# Release Scripts

This directory contains scripts for releasing fastcert to Cargo and Homebrew.

## Prerequisites

Before running the release script, ensure you have:

1. **Cargo login**: Authenticate with crates.io
   ```bash
   cargo login
   ```

2. **GitHub CLI**: Install and authenticate
   ```bash
   brew install gh
   gh auth login
   ```

3. **Git configured**: Ensure your git user is set
   ```bash
   git config user.name "Your Name"
   git config user.email "your.email@example.com"
   ```

4. **Clean working directory**: No uncommitted changes

## Release Process

### 1. Prepare the Release

Update CHANGELOG.md with the changes for the new version:

```markdown
## [1.0.0] - 2024-12-10

### Added
- New feature X
- New feature Y

### Fixed
- Bug fix Z
```

### 2. Run the Release Script

```bash
./scripts/release.sh 1.0.0
```

This script will:
1. ✅ Validate version format
2. ✅ Check for uncommitted changes
3. ✅ Update Cargo.toml and Cargo.lock
4. ✅ Run tests, clippy, and format checks
5. ✅ Commit version bump
6. ✅ Create and push git tag
7. ✅ Wait for CI to pass
8. ✅ Publish to crates.io
9. ✅ Create GitHub release
10. ✅ Generate Homebrew formula

### 3. Homebrew Distribution

After the release script completes, you have two options:

#### Option A: Create a Homebrew Tap (Recommended for initial releases)

1. Create a new repository named `homebrew-tap`
2. Create a `Formula` directory
3. Copy the generated formula:
   ```bash
   cp homebrew/fastcert.rb ../homebrew-tap/Formula/
   cd ../homebrew-tap
   git add Formula/fastcert.rb
   git commit -m "Add fastcert formula"
   git push
   ```
4. Users can install with:
   ```bash
   brew install ozankasikci/tap/fastcert
   ```

#### Option B: Submit to homebrew-core (For established projects)

1. Fork https://github.com/Homebrew/homebrew-core
2. Copy the formula to your fork:
   ```bash
   cp homebrew/fastcert.rb /path/to/homebrew-core/Formula/
   ```
3. Create a pull request
4. Wait for review and approval

### 4. Post-Release Verification

1. **Verify Cargo release**:
   ```bash
   cargo search fastcert
   ```

2. **Test Cargo installation**:
   ```bash
   cargo install fastcert
   fastcert --version
   ```

3. **Verify GitHub release**:
   - Visit https://github.com/ozankasikci/fastcert/releases

4. **Test Homebrew installation** (if using a tap):
   ```bash
   brew install ozankasikci/tap/fastcert
   fastcert --version
   ```

## Scripts

### release.sh

Main release script that orchestrates the entire release process.

**Usage:**
```bash
./scripts/release.sh <version>
```

**Example:**
```bash
./scripts/release.sh 1.0.0
```

### update-homebrew.sh

Generates or updates the Homebrew formula.

**Usage:**
```bash
./scripts/update-homebrew.sh <version>
```

**Example:**
```bash
./scripts/update-homebrew.sh 1.0.0
```

This script:
- Downloads the source tarball from GitHub
- Calculates SHA256 checksum
- Generates a Homebrew formula file
- Saves it to `homebrew/fastcert.rb`

## Troubleshooting

### "Tag already exists"

If you need to re-release a version:
```bash
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0
```

### "Permission denied" when publishing to crates.io

Make sure you're logged in:
```bash
cargo login
```

### CI failing

Wait for all GitHub Actions to pass before proceeding with `cargo publish`. The script will pause and ask you to confirm.

### Homebrew formula not working

Test the formula locally before distribution:
```bash
brew install --build-from-source homebrew/fastcert.rb
```

## Manual Release Steps

If you need to release manually:

### Cargo

```bash
# Update version in Cargo.toml
vim Cargo.toml

# Update Cargo.lock
cargo build --release

# Test
cargo test --all

# Publish
cargo publish
```

### GitHub Release

```bash
# Create tag
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0

# Create release via GitHub CLI
gh release create v1.0.0 --title "v1.0.0" --notes "Release notes here"
```

### Homebrew Formula

```bash
# Download tarball
curl -sL https://github.com/ozankasikci/fastcert/archive/refs/tags/v1.0.0.tar.gz -o fastcert.tar.gz

# Calculate SHA256
shasum -a 256 fastcert.tar.gz

# Update formula with new version and SHA256
vim homebrew/fastcert.rb
```

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)

Examples:
- `1.0.0` - Initial release
- `1.1.0` - New feature added
- `1.1.1` - Bug fix
- `2.0.0` - Breaking changes
