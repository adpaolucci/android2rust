# `android2rust` — Pure-Rust Native Win32 & Cross-Platform Iced ADB/Fastboot GUI, Offline Forensics Workstation, CLI & MCP Server

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://android2rust.guap.ca**](https://android2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/android2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/adpaolucci/android2rust/actions/workflows/ci.yml/badge.svg)](https://github.com/adpaolucci/android2rust/actions/workflows/ci.yml)

**Ready-to-submit WinGet & Homebrew manifests live in [`packaging/`](packaging/README.md).**
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Architecture: 7 Crates](https://img.shields.io/badge/Workspace-7%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/android2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/android2rust-mcp)

**`android2rust`** is a 100% pure-Rust desktop GUI wrapper, bidirectional ADB/Fastboot command & recipe orchestrator, live device telemetry runner, **offline Android forensics & artifact inspector** (`.apk`, `.ab` backups, SQLite `.db`, `shared_prefs` XML, `logcat`/`getprop`), air-gapped HTML/JSON/Markdown reporter, CLI, and **Model Context Protocol (MCP)** server. It ships **two specialized pure-Rust GUIs** sharing the same core engine:
1. **`android2rust-win32`** (**WinSafe `0.0.29`**) — Zero-GPU authentic native Win32 Common Controls GUI (ComCtl v6, Per-Monitor DPI v2, Vista+ COM dialogs), engineered for Windows Desktops, elevated Administrator sessions, Hyper-V/VMware VMs, and **Windows Server over RDP**.
2. **`android2rust-iced`** (**Iced `0.14`**) — Consistent cross-platform retained-mode GUI (`wgpu` + `tiny-skia` CPU fallback) shipping on **Linux**, **macOS**, and **Windows** (`android2rust gui --iced`).

Zero Electron, zero WebView2, zero Node.js, and zero Java/Python runtime overhead.

---

## Comparison: `android2rust` vs. Legacy Workflows

| Capability | `android2rust` (WinSafe + Iced) | Raw `adb` / `fastboot` CLI | Legacy Java/Electron GUIs | Ad-hoc Batch / Shell Scripts |
| :--- | :--- | :--- | :--- | :--- |
| **Windows Native & RDP Stability** | **Authentic Win32 (`winsafe`) — zero GPU/OpenGL crash risk over RDP/VMs** | Console only | JVM / Chromium memory bloat | None |
| **Cross-Platform Parity** | **Unified Iced 0.14 UI on Linux, macOS, and Windows (`tiny-skia` CPU fallback)** | Platform-Tools CLI | Often single-OS | `.bat` vs `.sh` split |
| **Pure-Rust Offline Forensics** | **Built-in `.apk` / `AndroidManifest.xml`, `.ab` zlib TAR, SQLite `.db`, `shared_prefs` XML inspector** | Requires external tools (`aapt2`, `abe.jar`, `sqlite3`) | None or external binaries | Manual pipelines |
| **Bidirectional `.a2r` & CLI Parser** | **Paste any `adb` / `fastboot` command or import `.a2r` recipes back into GUI** | Manual CLI recall | Static button wrappers | None |
| **Destructive Operation Guards** | **Mandatory Dry-Run pre-flight & explicit guard on `flash` / `erase` / `format` / `unlock` / `uninstall` / `restore`** | Immediate execution | Basic prompts | Manual confirmation |
| **Live Telemetry & Reports** | **Parsed device/package/prop/logcat records, SHA-256 chain-of-custody, air-gapped HTML/JSON/MD** | Plain text stream | Raw terminal pane | Plain log redirection |
| **AI Agent Integration** | **Native `stdio` MCP Server (`android2rust-mcp`, 10 tools)** | None | None | None |

---

## Workspace Architecture

```text
android2rust/
├── Cargo.toml                         # Workspace root manifest (7 modular crates)
├── mcp.json                           # Standard MCP server client configuration
├── crates/
│   ├── android2rust-core/             # Job schema, quoting, CLI & .a2r parser, validator, status decoder, pure-Rust APK/.ab/SQLite forensics, presets, profiles
│   ├── android2rust-runner/           # Platform-Tools probe (adb/fastboot), CREATE_NO_WINDOW streaming executor, dry-run & offline forensic runner, SHA-256
│   ├── android2rust-report/           # Self-contained offline HTML, JSON, and Markdown audit reports + direct artifact/log importer
│   ├── android2rust-mcp/              # Model Context Protocol (MCP) JSON-RPC 2.0 stdio server & standalone `android2rust-mcp` binary
│   ├── android2rust-cli/              # Unified CLI (`android2rust`): presets, build, parse, decode, inspect, dry-run, run, profile, report, env, mcp, gui
│   ├── android2rust-win32/            # Native zero-GPU Win32 desktop console on WinSafe 0.0.29 (`android2rust-win32`)
│   └── android2rust-iced/             # Cross-platform Iced 0.14 desktop console (`android2rust-iced`: Linux, macOS, Windows)
└── .github/workflows/                 # Cross-platform CI (`fmt`, `clippy`, `test`, `release`) and GitHub Release packaging
```

---

## Dual Desktop Consoles (`android2rust-win32` & `android2rust-iced`)

- **Default Launch**: Running `android2rust` with no arguments (or `android2rust gui`) launches **`android2rust-win32.exe`** on Windows and **`android2rust-iced`** on Linux/macOS.
- **Cross-Platform Iced on Windows**: Run `android2rust-iced.exe` directly or invoke `android2rust gui --iced` to launch the matching Iced UI on Windows (supports `ICED_BACKEND=tiny-skia` for software rendering fallback).

Both GUIs provide full feature parity across:
- **Designer & Diagnostics**: Job identity, 8 built-in presets (device triage, logcat capture, APK sideload/install, pull extraction, `.ab` backup, fastboot variables, safe boot flash preview, offline forensic audit), bidirectional CLI importer, persistent `%APPDATA%\android2rust\profiles.json`, Windows Task Scheduler (`schtasks /Create`) generator, and real-time validation diagnostics.
- **ADB & Packages**: `-s` serial / `-d` USB / `-e` emulator / `-t` transport ID targeting, `devices -l`, `getprop`, `pm list packages` filters (`-3`, `-s`, `-f`, `-i`, `-U`), `install` (`-r`, `-d`, `-g`, `--user`), `uninstall` (`-k`), `disable-user` / `enable`, `shell`, `dumpsys`, `sideload`, and `reboot` targets.
- **Transfer, Backup & Logcat**: `adb pull` / `adb push` (`-a` preserve timestamps, `-z` compression), `adb backup` / `adb restore` (`-apk`, `-obb`, `-shared`, `-all`, `-system`), `bugreport`, and `logcat` (`-b` buffers, `-d`, `-c`, `-v` format, `-t` max lines, filter specs).
- **Fastboot & Partitions**: `devices`, `getvar all`, `flash` (slot `--slot`, `--skip-reboot`, `--disable-verity`, `--disable-verification`), `boot`, `erase`, `format`, `flashing unlock/lock`, and `reboot` (`bootloader`, `fastbootd`, `recovery`).
- **Offline Forensics & Artifacts**: Pure-Rust zero-dependency inspection of local `.apk` archives (`AndroidManifest.xml` permissions, DEX/native `.so`/signature entries), Android `.ab` backups (header + zlib decompression + TAR entry table), SQLite `.db` files (page size, WAL mode, `CREATE TABLE` schema recovery), `shared_prefs` XML keys, and `logcat`/`getprop` dumps.
- **Live Console, Batch Queue & History**: Real-time output parsing, filterable extracted records table, raw console stream, ordered multi-job queue (`Stop on Error`), persistent run history, and one-click HTML/JSON/Markdown audit reports.

---

## Command-Line Interface (`android2rust`)

```powershell
# Launch the platform default Desktop GUI (WinSafe Win32 on Windows, Iced on Linux/macOS)
android2rust

# Launch the cross-platform Iced GUI explicitly on Windows
android2rust gui --iced

# List all 8 built-in presets
android2rust presets

# Probe ADB & Fastboot binaries on PATH / ANDROID_HOME
android2rust env

# Build and validate an ADB or Fastboot command, plus export .a2r / .bat / .ps1 / .sh / schtasks
android2rust build --preset apk-install-grant --source "C:\Apps\sample.apk" --serial R58M123ABC --export-ps1 install.ps1

# Parse any raw adb or fastboot command or .a2r recipe file into structured JSON
android2rust parse 'adb -s R58M123ABC install -r -g "C:\Apps\app-release.apk"' --json
android2rust parse workflow.a2r --recipe --json

# Decode an Android / ADB / Fastboot error or exit code
android2rust decode INSTALL_FAILED_VERSION_DOWNGRADE
android2rust decode DEVICE_UNAUTHORIZED

# Perform pure-Rust offline forensic inspection on an APK, .ab backup, SQLite .db, or log dump
android2rust inspect "C:\Evidence\backup.ab" --report "C:\Evidence\backup_audit.html"

# Run a non-destructive Dry-Run pre-flight simulation
android2rust dry-run --preset fastboot-flash-image --source "C:\Images\boot.img" --target boot

# Execute a destructive operation (requires explicit --yes)
android2rust run --preset fastboot-flash-image --source "C:\Images\boot.img" --target boot --yes --report flash_audit.html

# Convert an existing log file or artifact into HTML, JSON, and Markdown reports
android2rust report --log-file logcat.txt --output ./audit_bundle --format all

# Start the stdio MCP server
android2rust mcp
```

---

## Model Context Protocol (`android2rust-mcp`)

Add `mcp.json` to your MCP-compatible client (`command: "android2rust"`, `args: ["mcp"]`) to expose 10 structured tools:

1. `android2rust_environment` — Host OS, `adb` / `fastboot` binary paths & SDK detection
2. `android2rust_presets` — Built-in ADB, Fastboot, and Forensic templates
3. `android2rust_build_command` — Validated command, `.a2r`, `.bat`, `.ps1`, `.sh`, and `schtasks` generator
4. `android2rust_parse_command` — Command-line / `.a2r` parser + validation diagnostics
5. `android2rust_decode_status` — Android/ADB/Fastboot status & exit-code decoder
6. `android2rust_profiles` — Persistent profile CRUD (`list`, `get`, `save`, `delete`)
7. `android2rust_inspect_artifact` — Pure-Rust offline `.apk` / `.ab` / `.db` / XML / log forensic inspector
8. `android2rust_dry_run` — Safe non-destructive pre-flight simulation
9. `android2rust_run` — Live execution with strict `confirm_destructive: true` refusal guard for destructive ADB/Fastboot operations
10. `android2rust_report` — Offline HTML / JSON / Markdown audit generator

---

## Building from Source

Requires Rust `1.88+` (2024 edition).

```powershell
git clone https://github.com/adpaolucci/android2rust.git
cd android2rust
cargo test --workspace
cargo build --workspace --release
```

Compiled binaries are emitted to `target\release\`:
- `android2rust.exe` (Unified CLI & GUI launcher)
- `android2rust-win32.exe` (Native zero-GPU Win32 Desktop Console via WinSafe)
- `android2rust-iced.exe` (Cross-platform Iced 0.14 Desktop Console)
- `android2rust-mcp.exe` (Standalone `stdio` MCP server)

## License

Licensed under the [Apache License, Version 2.0](LICENSE) (see also [NOTICE](NOTICE)).
