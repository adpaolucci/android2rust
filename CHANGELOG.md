# Changelog

All notable changes to `android2rust` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-19

### Added
- **Modular 7-Crate Pure-Rust Workspace (MSRV `1.88`)**: `android2rust-core`, `android2rust-runner`, `android2rust-report`, `android2rust-mcp`, `android2rust-cli`, `android2rust-win32`, and `android2rust-iced`.
- **ADB, Fastboot & Forensic Job Engine (`android2rust-core`)**: Covers `adb` (devices, props, packages, APK install/uninstall/disable, push/pull, `.ab` backup/restore, logcat, bugreport, dumpsys, sideload, shell, reboot), `fastboot` (devices, getvar, flash, boot, erase, format, unlock/lock, reboot), and pure-Rust offline artifact inspection (`.apk`/ZIP + `AndroidManifest.xml` permissions, `.ab` zlib TAR backup unpacking, SQLite 3 schema/WAL header inspection, `shared_prefs` XML keys, and `getprop`/`logcat` dumps), plus bidirectional CLI & `.a2r` recipe parsers, `.bat`/`.ps1`/`.sh`/`schtasks` exports, status-code decoder, 8 presets, and persistent profiles/history.
- **Live Streaming Runner & Offline Forensic Executor (`android2rust-runner`)**: Discovers `adb` and `fastboot` from `PATH` and Android SDK locations, runs with `CREATE_NO_WINDOW` on Windows, parses device rows, `getprop`, `pm list packages`, transfer `%`, `logcat`, and `fastboot` output in real time, supports non-destructive dry-run simulation and offline forensic execution, and computes SHA-256 chain-of-custody hashes.
- **Air-Gapped Audit Reports (`android2rust-report`)**: Generates standalone offline HTML (with interactive filtering and light/dark toggle), JSON, and Markdown audit reports from live runs, log files, or raw `.apk`/`.ab`/`.db` artifacts.
- **Model Context Protocol Server (`android2rust-mcp` & `android2rust mcp`)**: JSON-RPC 2.0 `stdio` MCP server exposing 10 tools with explicit `confirm_destructive` safety enforcement for destructive ADB and Fastboot operations.
- **Native Win32 Desktop Console (`android2rust-win32`)**: Zero-GPU WinSafe `0.0.29` Win32 Common Controls GUI (ComCtl v6 + Per-Monitor DPI v2 manifest, Vista+ COM dialogs, `run_ui_thread` live stream relay, `MessageBox` destructive confirmation).
- **Cross-Platform Iced Desktop Console (`android2rust-iced`)**: Retained-mode Iced `0.14` (`wgpu` + `tiny-skia` CPU fallback) desktop console shipping across Linux, macOS, and Windows (`android2rust gui --iced`), featuring Light/Dark mode, full ADB/Fastboot/Forensic tabs, live stream, batch queue, run history, and modal overlays.
- **CLI Suite & Packaging (`android2rust`)**: 12 CLI subcommands with two-stage `Ctrl+C` cancellation, cross-platform GitHub Actions CI/Release workflows, and WinGet / Homebrew packaging manifests.
