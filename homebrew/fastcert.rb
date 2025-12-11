class Fastcert < Formula
  desc "Simple zero-config tool for making locally-trusted development certificates"
  homepage "https://github.com/ozankasikci/fastcert"
  version "0.3.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.3.1/fastcert-x86_64-apple-darwin.tar.gz"
      sha256 "8d617da76c4e323b3828a6fbf02e5f8cdb21396bbf6bac0f4fc7042cc1c6cf72"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.3.1/fastcert-aarch64-apple-darwin.tar.gz"
      sha256 "23fb0e64a4289de76cfe5ebcf1559cc8b56bd992a6b47702640a2d3ed7155ecb"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.3.1/fastcert-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "89a777af5a97a8f8217b2fa06c74a101a9e69d423298605764a94b4e2bb72fd4"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.3.1/fastcert-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "525d8ae909cef6980a3916630e8febe0893670d2591bf65ffb7e9dc3025a5ba9"
    end
  end

  def install
    bin.install "fastcert"
  end

  test do
    system "#{bin}/fastcert", "-CAROOT"
  end
end
