class Fastcert < Formula
  desc "Simple zero-config tool for making locally-trusted development certificates"
  homepage "https://github.com/ozankasikci/fastcert"
  version "0.1.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.1.1/fastcert-x86_64-apple-darwin.tar.gz"
      sha256 "ea64158bcbd3cdf8847e681504b4d4c58e0941983e9380ced6a6994f314e1733"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.1.1/fastcert-aarch64-apple-darwin.tar.gz"
      sha256 "0f5b7e7c1de027e0b1f2ac79a11b17c33e9937662582d682afa0a18f0e24e974"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.1.1/fastcert-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d27489545509b84d579a481525e533f51e20cd2381579c2873bfc7a4d890d6da"
    end
  end

  def install
    bin.install "fastcert"
  end

  test do
    system "#{bin}/fastcert", "-CAROOT"
  end
end
