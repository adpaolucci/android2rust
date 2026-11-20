# Packaging Manifests (`WinGet` & `Homebrew`)

This directory stores ready-to-submit package manager manifests matching published GitHub Releases for **`android2rust`**.

## 1. Windows Package Manager (`winget`)

Validate and submit the YAML manifests in `packaging/winget/manifests/a/adpaolucci/android2rust/<version>/`:

```powershell
# Local validation using winget CLI
winget validate --manifest .\packaging\winget\manifests\a\adpaolucci\android2rust\0.1.0

# Or submit an automated PR to microsoft/winget-pkgs using wingetcreate
wingetcreate submit .\packaging\winget\manifests\a\adpaolucci\android2rust\0.1.0
```

Installed portable command aliases: `android2rust`, `android2rust-win32`, `android2rust-iced`, `android2rust-mcp`.

## 2. Homebrew (`macOS` & `Linux`)

Copy `packaging/homebrew/android2rust.rb` into `Formula/android2rust.rb` of a tap repository (e.g., `adpaolucci/homebrew-tap`):

```bash
brew install adpaolucci/tap/android2rust
# Or test locally directly from file:
brew install --formula ./packaging/homebrew/android2rust.rb
brew test android2rust
```
