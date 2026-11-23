# Contributing to `android2rust`

Thank you for your interest in contributing to `android2rust`!

## Code Architecture

The workspace is organized into 7 modular crates:
- `crates/android2rust-core`: Job schema, Windows/POSIX quoting & command builder, bidirectional CLI & `.a2r` recipe parsers, validation rules, Android/ADB/Fastboot status decoder, pure-Rust offline forensic parsers (`.apk` AXML/ABX\0/`Sig Block 42`, `bugreport.zip`, encrypted `.ab` PBKDF2/AES-256-CBC decryption, SQLite `.db`, `shared_prefs` XML, `logcat`/`getprop`), built-in presets, and persistent profile/history store.
- `crates/android2rust-runner`: Android Platform-Tools environment detector (`adb` & `fastboot`), real-time streaming executor (`CREATE_NO_WINDOW` on Windows), stateful ADB/Fastboot output parser, dry-run simulator, offline forensic runner, and dual SHA-256 + SHA-512 log/artifact hashing.
- `crates/android2rust-report`: Self-contained offline HTML, JSON, Markdown, and chronological timeline CSV/JSONL audit report generators plus direct `.apk`/`.ab`/`.db`/`bugreport.zip`/log importer.
- `crates/android2rust-mcp`: Model Context Protocol (MCP) JSON-RPC 2.0 `stdio` server exposing 10 tools (`android2rust-mcp`).
- `crates/android2rust-cli`: Unified command-line interface binary (`android2rust`) that launches `android2rust-win32` (Windows default) or `android2rust-iced` (Linux/macOS or `--iced`) when invoked with no arguments.
- `crates/android2rust-win32`: Native zero-GPU Win32 desktop console built on `winsafe` (`android2rust-win32`).
- `crates/android2rust-iced`: Cross-platform retained-mode desktop console built on `iced` (`android2rust-iced`).

## Development Workflow

1. Fork and clone the repository.
2. Ensure you have a recent stable Rust toolchain installed (`rustup update stable`).
3. Create a feature branch (`git checkout -b feature/my-enhancement`).
4. Run checks, linter, and tests:
   ```bash
   cargo check --workspace --all-targets
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
5. Commit with clear, descriptive commit messages and open a Pull Request on GitHub.

## Guidelines
- **Safety First**: Any path that executes destructive Android commands (`fastboot flash`, `fastboot erase`, `fastboot format`, `fastboot flashing unlock`, `adb uninstall`, `adb restore`, or destructive shell commands) must provide non-destructive Dry-Run previewing and explicit destructive confirmation in Win32 GUI, Iced GUI, CLI, and MCP.
- **Zero WebView / Zero External Runtime**: All GUI rendering, parsing, forensic inspection (`.apk`, `.ab`, SQLite headers), validation, and report generation remain 100% pure Rust.
- **Logging**: Use `tracing` macros writing diagnostics to `stderr` so CLI `stdout` and MCP `stdio` streams remain clean.
