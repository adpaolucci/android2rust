class Android2rust < Formula
  desc "Pure-Rust Iced GUI, ADB/Fastboot device orchestrator, offline APK/.ab/SQLite forensics workstation, and MCP server"
  homepage "https://android2rust.guap.ca"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/android2rust/releases/download/v0.1.0/android2rust-aarch64-apple-darwin.tar.gz"
      sha256 "6d53686fd6d6d70a58f3faf0a36d97e56d8560122ea10720a4ee01cc3d6a4c0e"
    else
      url "https://github.com/adpaolucci/android2rust/releases/download/v0.1.0/android2rust-x86_64-apple-darwin.tar.gz"
      sha256 "ba269404f81223efde4b3917bd9cda2078bce14d82d6e6c898578eb1f523bb50"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/android2rust/releases/download/v0.1.0/android2rust-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b4900cd77a296cfb86bfd29a0c577a59f63fb2adc82cdec8dcc9287d522359dd"
    end
  end

  def install
    bin.install "android2rust"
    bin.install "android2rust-iced"
    bin.install "android2rust-mcp"
    doc.install "README.md", "CHANGELOG.md"
    doc.install "SBOM-crates.txt" if File.exist?("SBOM-crates.txt")
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "android2rust", shell_output("#{bin}/android2rust --help")
    assert_match "INSTALL_FAILED_INSUFFICIENT_STORAGE", shell_output("#{bin}/android2rust decode INSTALL_FAILED_INSUFFICIENT_STORAGE")
    assert_match "android2rust-iced", shell_output("#{bin}/android2rust-iced --help")
  end
end
