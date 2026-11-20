class Android2rust < Formula
  desc "Pure-Rust Iced GUI, ADB/Fastboot device orchestrator, offline APK/.ab/SQLite forensics workstation, and MCP server"
  homepage "https://android2rust.guap.ca"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/android2rust/releases/download/v0.1.0/android2rust-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/adpaolucci/android2rust/releases/download/v0.1.0/android2rust-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/android2rust/releases/download/v0.1.0/android2rust-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "android2rust"
    bin.install "android2rust-iced"
    bin.install "android2rust-mcp"
    doc.install "README.md", "CHANGELOG.md"
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "android2rust", shell_output("#{bin}/android2rust --help")
    assert_match "INSTALL_FAILED_INSUFFICIENT_STORAGE", shell_output("#{bin}/android2rust decode INSTALL_FAILED_INSUFFICIENT_STORAGE")
    assert_match "android2rust-iced", shell_output("#{bin}/android2rust-iced --help")
  end
end
