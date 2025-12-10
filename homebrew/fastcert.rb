class Fastcert < Formula
  desc "Simple zero-config tool for making locally-trusted development certificates"
  homepage "https://github.com/ozankasikci/fastcert"
  version "0.1.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.1.2/fastcert-x86_64-apple-darwin.tar.gz"
      sha256 "7024b47f3b50db85ee2b783d9b2754bc55cccc5b321a0a3ece5bec5cf9506966"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.1.2/fastcert-aarch64-apple-darwin.tar.gz"
      sha256 "d8bcba75ff9dfc499bf4ad2f1832fce841809497f2c9265b58b6f9ae03d93c63"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.1.2/fastcert-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "04757d551370b600d99d51c27e40698aee6b374da0d55c3275206a91973a696b"
    else
      url "https://github.com/ozankasikci/fastcert/releases/download/v0.1.2/fastcert-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c570b47daa7846c810304ee76e2e883a9be3ab5ed2d2f0a731b39a600f14a48e"
    end
  end

  def install
    bin.install "fastcert"
  end

  test do
    system "#{bin}/fastcert", "-CAROOT"
  end
end
