class Fastcert < Formula
  desc "Simple zero-config tool for making locally-trusted development certificates"
  homepage "https://github.com/ozankasikci/fastcert"
  version "0.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.2.0/fastcert-x86_64-apple-darwin.tar.gz"
      sha256 "33cb9e043d7bffe8c0330e69999810895ba402cdcd5b806c6d3fcdfd0012178f"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.2.0/fastcert-aarch64-apple-darwin.tar.gz"
      sha256 "b04e2030df3bccbbb254328528d73742aa4b9d0542b70daca0cc0ea5c7be64dd"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.2.0/fastcert-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "e7d7ac8a96504f3e6ad2fd83d28120e8f96b11691d0c85cdedb50d92e79b64d1"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.2.0/fastcert-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "619b6340f76b33f33f2694e7679845dba7bfe6c1f90aa1f238d24a4626c23e9f"
    end
  end

  def install
    bin.install "fastcert"
  end

  test do
    system "#{bin}/fastcert", "-CAROOT"
  end
end
