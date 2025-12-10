#!/bin/bash
set -e

# Update Homebrew formula for fastcert
# Usage: ./scripts/update-homebrew.sh <version>

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Error: Version number required"
    echo "Usage: ./scripts/update-homebrew.sh <version>"
    exit 1
fi

echo "🍺 Updating Homebrew formula for version $VERSION..."

# Download pre-built binaries and calculate SHA256
echo "📥 Downloading pre-built binaries..."

TEMP_DIR=$(mktemp -d)

# macOS Intel (x86_64)
MACOS_INTEL_URL="https://github.com/ozankasikci/fastcert/releases/download/v${VERSION}/fastcert-x86_64-apple-darwin.tar.gz"
echo "  Downloading macOS Intel..."
curl -sL "$MACOS_INTEL_URL" -o "$TEMP_DIR/macos-intel.tar.gz"

# macOS Apple Silicon (aarch64)
MACOS_ARM_URL="https://github.com/ozankasikci/fastcert/releases/download/v${VERSION}/fastcert-aarch64-apple-darwin.tar.gz"
echo "  Downloading macOS ARM..."
curl -sL "$MACOS_ARM_URL" -o "$TEMP_DIR/macos-arm.tar.gz"

# Linux x86_64
LINUX_URL="https://github.com/ozankasikci/fastcert/releases/download/v${VERSION}/fastcert-x86_64-unknown-linux-gnu.tar.gz"
echo "  Downloading Linux x86_64..."
curl -sL "$LINUX_URL" -o "$TEMP_DIR/linux.tar.gz"

echo "🔐 Calculating SHA256..."
if command -v shasum >/dev/null 2>&1; then
    MACOS_INTEL_SHA256=$(shasum -a 256 "$TEMP_DIR/macos-intel.tar.gz" | awk '{print $1}')
    MACOS_ARM_SHA256=$(shasum -a 256 "$TEMP_DIR/macos-arm.tar.gz" | awk '{print $1}')
    LINUX_SHA256=$(shasum -a 256 "$TEMP_DIR/linux.tar.gz" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    MACOS_INTEL_SHA256=$(sha256sum "$TEMP_DIR/macos-intel.tar.gz" | awk '{print $1}')
    MACOS_ARM_SHA256=$(sha256sum "$TEMP_DIR/macos-arm.tar.gz" | awk '{print $1}')
    LINUX_SHA256=$(sha256sum "$TEMP_DIR/linux.tar.gz" | awk '{print $1}')
else
    echo "Error: Neither shasum nor sha256sum found"
    rm -rf "$TEMP_DIR"
    exit 1
fi

rm -rf "$TEMP_DIR"

echo "  ✓ macOS Intel SHA256: $MACOS_INTEL_SHA256"
echo "  ✓ macOS ARM SHA256: $MACOS_ARM_SHA256"
echo "  ✓ Linux SHA256: $LINUX_SHA256"

# Create homebrew directory if it doesn't exist
mkdir -p homebrew

# Generate Homebrew formula
echo "📝 Generating Homebrew formula..."
cat > homebrew/fastcert.rb << EOF
class Fastcert < Formula
  desc "Simple zero-config tool for making locally-trusted development certificates"
  homepage "https://github.com/ozankasikci/fastcert"
  version "${VERSION}"
  license "MIT"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v${VERSION}/fastcert-x86_64-apple-darwin.tar.gz"
      sha256 "${MACOS_INTEL_SHA256}"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v${VERSION}/fastcert-aarch64-apple-darwin.tar.gz"
      sha256 "${MACOS_ARM_SHA256}"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v${VERSION}/fastcert-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "${LINUX_SHA256}"
    end
  end

  def install
    bin.install "fastcert"
  end

  test do
    system "#{bin}/fastcert", "-CAROOT"
  end
end
EOF

echo "✅ Formula generated at homebrew/fastcert.rb"
echo ""
echo "📋 Next steps for Homebrew distribution:"
echo ""
echo "Option 1: Create a Homebrew Tap (Recommended for initial releases)"
echo "  1. Create a new repository: homebrew-tap"
echo "  2. Copy homebrew/fastcert.rb to Formula/fastcert.rb"
echo "  3. Users can install with: brew install ozankasikci/tap/fastcert"
echo ""
echo "Option 2: Submit to homebrew-core (For established projects)"
echo "  1. Fork https://github.com/Homebrew/homebrew-core"
echo "  2. Copy homebrew/fastcert.rb to Formula/fastcert.rb"
echo "  3. Create a pull request"
echo "  4. Wait for review and approval"
echo ""
echo "For now, commit the formula to this repository:"
echo "  git add homebrew/fastcert.rb"
echo "  git commit -m 'chore: update homebrew formula for v${VERSION}'"
echo "  git push"
echo ""
