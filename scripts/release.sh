#!/bin/bash
set -e

# Release script for fastcert
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 1.0.0

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Error: Version number required"
    echo "Usage: ./scripts/release.sh <version>"
    echo "Example: ./scripts/release.sh 1.0.0"
    exit 1
fi

# Validate version format (semver)
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "Error: Invalid version format. Use semantic versioning (e.g., 1.0.0)"
    exit 1
fi

echo "🚀 Starting release process for version $VERSION"
echo ""

# Check if we're on master branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "master" ]; then
    echo "⚠️  Warning: You are not on master branch (current: $CURRENT_BRANCH)"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "Error: You have uncommitted changes. Please commit or stash them first."
    exit 1
fi

# Check if tag already exists
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
    echo "Error: Tag v$VERSION already exists"
    exit 1
fi

# Update version in Cargo.toml
echo "📝 Updating version in Cargo.toml..."
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
rm Cargo.toml.bak

# Update Cargo.lock
echo "📦 Updating Cargo.lock..."
cargo build --release

# Run tests
echo "🧪 Running tests..."
cargo test --all

# Run clippy
echo "🔍 Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

# Run format check
echo "✨ Checking formatting..."
cargo fmt --all -- --check

# Commit version bump
echo "💾 Committing version bump..."
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to $VERSION"

# Create git tag
echo "🏷️  Creating git tag v$VERSION..."
git tag -a "v$VERSION" -m "Release version $VERSION"

# Push changes and tag
echo "⬆️  Pushing to GitHub..."
git push origin master
git push origin "v$VERSION"

# Wait for GitHub Actions to complete
echo ""
echo "⏳ Waiting for GitHub Actions to complete..."
echo "   Check: https://github.com/ozankasikci/fastcert/actions"
echo ""
read -p "Press enter when CI is green to continue with publishing..."

# Publish to crates.io
echo ""
echo "📦 Publishing to crates.io..."
cargo publish

echo ""
echo "✅ Cargo publish complete!"
echo ""
echo "⏳ Waiting for crates.io to process the release (this can take a few minutes)..."
sleep 30

# Create GitHub release
echo ""
echo "🎉 Creating GitHub release..."
gh release create "v$VERSION" \
    --title "v$VERSION" \
    --notes "Release $VERSION

## Installation

### Cargo
\`\`\`bash
cargo install fastcert
\`\`\`

### Homebrew
\`\`\`bash
brew install fastcert
\`\`\`

### From Source
\`\`\`bash
git clone https://github.com/ozankasikci/fastcert
cd fastcert
cargo install --path .
\`\`\`

See the [CHANGELOG](https://github.com/ozankasikci/fastcert/blob/master/CHANGELOG.md) for details."

# Update Homebrew formula
echo ""
echo "🍺 Updating Homebrew formula..."
./scripts/update-homebrew.sh "$VERSION"

echo ""
echo "✅ Release $VERSION completed successfully!"
echo ""
echo "📋 Next steps:"
echo "  1. Verify the release on crates.io: https://crates.io/crates/fastcert"
echo "  2. Verify the GitHub release: https://github.com/ozankasikci/fastcert/releases/tag/v$VERSION"
echo "  3. Test Homebrew installation: brew install fastcert"
echo "  4. Update CHANGELOG.md if needed"
echo ""
