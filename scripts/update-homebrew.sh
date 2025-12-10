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

# Download the source tarball from GitHub
TARBALL_URL="https://github.com/ozankasikci/fastcert/archive/refs/tags/v${VERSION}.tar.gz"
TEMP_FILE=$(mktemp)

echo "📥 Downloading source tarball..."
curl -sL "$TARBALL_URL" -o "$TEMP_FILE"

# Calculate SHA256
echo "🔐 Calculating SHA256..."
if command -v shasum >/dev/null 2>&1; then
    SHA256=$(shasum -a 256 "$TEMP_FILE" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    SHA256=$(sha256sum "$TEMP_FILE" | awk '{print $1}')
else
    echo "Error: Neither shasum nor sha256sum found"
    rm "$TEMP_FILE"
    exit 1
fi

rm "$TEMP_FILE"

echo "✅ SHA256: $SHA256"

# Create homebrew directory if it doesn't exist
mkdir -p homebrew

# Generate Homebrew formula
echo "📝 Generating Homebrew formula..."
cat > homebrew/fastcert.rb << EOF
class Fastcert < Formula
  desc "Simple zero-config tool for making locally-trusted development certificates"
  homepage "https://github.com/ozankasikci/fastcert"
  url "https://github.com/ozankasikci/fastcert/archive/refs/tags/v${VERSION}.tar.gz"
  sha256 "${SHA256}"
  license "MIT"
  head "https://github.com/ozankasikci/fastcert.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    # Test that the binary exists and runs
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
