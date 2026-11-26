# `android2rust` — Pure-Rust Native Win32 & Cross-Platform Iced ADB/Fastboot GUI, Offline Forensics Workstation, CLI & MCP Server

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://android2rust.guap.ca**](https://android2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/android2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/adpaolucci/android2rust/actions/workflows/ci.yml/badge.svg)](https://github.com/adpaolucci/android2rust/actions/workflows/ci.yml)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.89%2B)-orange.svg)](Cargo.toml)
[![Architecture: 8 Crates](https://img.shields.io/badge/Workspace-8%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/android2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0%20(13%20Tools)-purple.svg)](crates/android2rust-mcp)

**Ready-to-submit WinGet & Homebrew manifests live in [`packaging/`](packaging/README.md).**

**`android2rust`** is a 100% pure-Rust desktop GUI wrapper, bidirectional ADB/Fastboot command & recipe orchestrator, live device telemetry runner, **offline Android forensics & artifact inspector** (`.apk`, `.ab` backups, Android 12+ `ABX\0`, `adb bugreport` ZIPs, SQLite `.db`, `shared_prefs` XML, `logcat`/`getprop`), air-gapped HTML/JSON/Markdown/Timeline reporter, CLI, and **Model Context Protocol (MCP)** server. It ships **two specialized pure-Rust GUIs** sharing the same core engine:
1. **`android2rust-win32`** (**WinSafe `0.0.29`**) — Zero-GPU authentic native Win32 Common Controls GUI (ComCtl v6, Per-Monitor DPI v2, Vista+ COM dialogs), engineered for Windows Desktops, elevated Administrator sessions, Hyper-V/VMware VMs, and **Windows Server over RDP**.
2. **`android2rust-iced`** (**Iced `0.14`**) — Consistent cross-platform retained-mode GUI (`wgpu` + `tiny-skia` CPU fallback) shipping on **Linux**, **macOS**, and **Windows** (`android2rust gui --iced`).

Zero Electron, zero WebView2, zero Node.js, and zero Java/Python runtime overhead.

---

## Comparison: `android2rust` vs. Legacy Workflows

| Capability | `android2rust` (WinSafe + Iced) | Raw `adb` / `fastboot` CLI | Legacy Java/Electron GUIs | Ad-hoc Batch / Shell Scripts |
| :--- | :--- | :--- | :--- | :--- |
| **Windows Native & RDP Stability** | **Authentic Win32 (`winsafe`) — zero GPU/OpenGL crash risk over RDP/VMs** | Console only | JVM / Chromium memory bloat | None |
| **Cross-Platform Parity** | **Unified Iced 0.14 UI on Linux, macOS, and Windows (`tiny-skia` CPU fallback)** | Platform-Tools CLI | Often single-OS | `.bat` vs `.sh` split |
| **Pure-Rust Offline Forensics** | **Hardened `#![forbid(unsafe_code)]` inspector: `.apk` (AXML security flags, `APK Sig Block 42` v2/v3/v3.1, Janus & Zip-Slip/mismatch checks), Android 12+ `ABX\0`, `bugreport` ZIPs, `.ab` PBKDF2/AES-256-CBC decryption, SQLite freelist + `-wal`/`-shm`/`-journal`, `shared_prefs` XML** | Requires external tools (`aapt2`, `abe.jar`, `sqlite3`, `abx2xml`) | None or external binaries | Manual pipelines |
| **Bidirectional `.a2r` & CLI Parser** | **Paste any `adb` / `fastboot` command or import `.a2r` recipes back into GUI** | Manual CLI recall | Static button wrappers | None |
| **Destructive Operation Guards** | **Mandatory Dry-Run pre-flight & explicit guard on `flash` / `erase` / `format` / `unlock` / `uninstall` / `restore`** | Immediate execution | Basic prompts | Manual confirmation |
| **Live Telemetry & Reports** | **Parsed device/package/prop/logcat records, dual SHA-256 + SHA-512 custody, case provenance, air-gapped HTML/JSON/MD + CSV/JSONL timelines** | Plain text stream | Raw terminal pane | Plain log redirection |
| **AI Agent Integration** | **Native `stdio` MCP Server (`android2rust-mcp`, 13 tools)** | None | None | None |

---

## Workspace Architecture

```text
android2rust/
├── Cargo.toml                         # Workspace root manifest (8 modular crates)
├── mcp.json                           # Standard MCP server client configuration
├── crates/
│   ├── android2rust-core/             # Job schema, quoting, CLI & .a2r parser, validator, status decoder, pure-Rust APK/.ab/SQLite forensics, presets, profiles
│   ├── android2rust-runner/           # Platform-Tools probe (adb/fastboot), CREATE_NO_WINDOW streaming executor, dry-run & offline forensic runner, SHA-256
│   ├── android2rust-wpd/              # WPD/MTP File Search: Windows Portable Devices (WPD/MTP) enumerator, search, safe copy-out, guap-table & offline fixtures
│   ├── android2rust-report/           # Self-contained offline HTML, JSON, and Markdown audit reports + guap-export adapter
│   ├── android2rust-mcp/              # Model Context Protocol (MCP) JSON-RPC 2.0 stdio server (`android2rust-mcp`, 13 tools)
│   ├── android2rust-cli/              # Unified CLI (`android2rust`): presets, build, parse, decode, inspect, dry-run, run, profile, report, env, mtp, mcp, gui
│   ├── android2rust-win32/            # Native zero-GPU Win32 desktop console on WinSafe 0.0.29 (`android2rust-win32`) + guap-gui-win32
│   └── android2rust-iced/             # Cross-platform Iced 0.14 desktop console (`android2rust-iced` + Mobile Search view via guap-gui-iced)
└── .github/workflows/                 # Cross-platform CI (`fmt`, `clippy`, `test`, `release`) and GitHub Release packaging
```

---

## Dual Desktop Consoles (`android2rust-win32` & `android2rust-iced`)

- **Default Launch**: Running `android2rust` with no arguments (or `android2rust gui`) launches **`android2rust-win32.exe`** on Windows and **`android2rust-iced`** on Linux/macOS.
- **Cross-Platform Iced on Windows**: Run `android2rust-iced.exe` directly or invoke `android2rust gui --iced` to launch the matching Iced UI on Windows (supports `ICED_BACKEND=tiny-skia` for software rendering fallback).

Both GUIs provide full feature parity across:
- **Designer & Diagnostics**: Job identity, 8 built-in presets (device triage, props fingerprint, 3rd-party package audit, APK install/grant, logcat crash snapshot, pull evidence, guarded fastboot flash preview, and offline forensic audit), bidirectional CLI importer, persistent `%APPDATA%\android2rust\profiles.json`, Windows Task Scheduler (`schtasks /Create`) generator, and real-time validation diagnostics.
- **ADB & Packages**: `-s` serial / `-d` USB / `-e` emulator / `-t` transport ID targeting, `devices -l`, `getprop`, `pm list packages` filters (`-3`, `-s`, `-f`, `-i`, `-U`), `install` (`-r`, `-d`, `-g`, `--user`), `uninstall` (`-k`), `disable-user` / `enable`, `shell`, `dumpsys`, `sideload`, and `reboot` targets.
- **Transfer, Backup & Logcat**: `adb pull` / `adb push` (`-a` preserve timestamps, `-z` compression), `adb backup` / `adb restore` (`-apk`, `-obb`, `-shared`, `-all`, `-system`), `bugreport`, and `logcat` (`-b` buffers, `-d`, `-c`, `-v` format, `-t` max lines, filter specs).
- **Fastboot & Partitions**: `devices`, `getvar all`, `flash` (slot `--slot`, `--skip-reboot`, `--disable-verity`, `--disable-verification`, `-w`), `boot`, `erase`, `format`, `flashing unlock/lock`, and `reboot` (`bootloader`, `fastbootd`, `recovery`).
- **Offline Forensics & Provenance**: Pure-Rust zero-dependency inspection of local `.apk` archives (`AndroidManifest.xml` AXML security flags & permissions, DEX/native `.so` ABIs, v1 + `APK Sig Block 42` v2/v3/v3.1 signatures), `.ab` backups (plain and PBKDF2/AES-256-CBC decrypted via RAM-only passphrase), Android 12+ `ABX\0`, `adb bugreport` `.zip` dumps, SQLite `.db` files (page size, freelist pages, `user_version`, `application_id`, WAL mode, `CREATE TABLE` schema recovery, `-wal`/`-shm`/`-journal` digests), `shared_prefs` XML keys, `logcat`/`getprop` dumps, plus Case Provenance (`Case ID`, `Evidence ID`, `Examiner`) fields.
- **Live Console, Batch Queue & History**: Real-time output parsing, filterable extracted records table, raw console stream, ordered multi-job queue (`Stop on Error`), persistent run history, and one-click HTML/JSON/Markdown + chronological Timeline CSV/JSONL audit reports.

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

# Perform pure-Rust offline forensic inspection on an APK, .ab (optionally decrypted), ABX, bugreport ZIP, SQLite .db, or log dump
android2rust inspect "C:\Evidence\backup.ab" --password "backup_pass" --case-id "IR-2026" --report "C:\Evidence\backup_audit.html" --timeline "C:\Evidence\timeline.csv"

# Run a non-destructive Dry-Run pre-flight simulation
android2rust dry-run --preset fastboot-flash-image --source "C:\Images\boot.img" --target boot

# Execute a destructive operation (requires explicit --yes)
android2rust run --preset fastboot-flash-image --source "C:\Images\boot.img" --target boot --yes --report flash_audit.html

# Convert an existing log file or artifact into HTML, JSON, Markdown, or timeline reports
android2rust report --log-file logcat.txt --output ./audit_bundle --format all --timeline events.jsonl

# WPD/MTP File Search (live devices or deterministic offline --source-dir fixture)
android2rust mtp devices --json
android2rust mtp search --source-dir .\wpd_fixture --format csv --output .\mobile_files.csv --json

# Start the stdio MCP server
android2rust mcp
```

---

## Model Context Protocol (`android2rust-mcp`)

Add `mcp.json` to your MCP-compatible client (`command: "android2rust"`, `args: ["mcp"]`) to expose **13 structured tools**:

1. `android2rust_environment` — Host OS, `adb` / `fastboot` binary paths & SDK detection
2. `android2rust_presets` — Built-in ADB, Fastboot, and Forensic templates
3. `android2rust_build_command` — Validated command, `.a2r`, `.bat`, `.ps1`, `.sh`, and `schtasks` generator
4. `android2rust_parse_command` — Command-line / `.a2r` parser + validation diagnostics
5. `android2rust_decode_status` — Android/ADB/Fastboot status & exit-code decoder
6. `android2rust_profiles` — Persistent profile CRUD (`list`, `get`, `save`, `delete`)
7. `android2rust_inspect_artifact` — Pure-Rust offline `.apk` / `.ab` / `ABX` / `bugreport.zip` / `.db` / XML / log forensic inspector (with `ab_password`, `case_id`, `evidence_id`, `examiner`)
8. `android2rust_dry_run` — Safe non-destructive pre-flight simulation (with optional `ab_password`, `case_id`, `evidence_id`, `examiner`)
9. `android2rust_run` — Live execution (with optional `ab_password`, `case_id`, `evidence_id`, `examiner`) and strict `confirm_destructive: true` refusal guard
10. `android2rust_report` — Validated offline HTML / JSON / Markdown / Timeline CSV & JSONL audit generator
11. `android2rust_wpd_devices` — Enumerate connected Windows Portable Devices (WPD/MTP) & storages (`readOnlyHint: true`)
12. `android2rust_mobile_file_search` — Search WPD/MTP devices or offline fixtures with wildcard/regex/size/date filters (`readOnlyHint: true`)
13. `android2rust_wpd_delete` — Policy-gated WPD/MTP file deletion (`-32003` enforced unless `AllowMutating` + `confirm_destructive: true`)

---

## Building from Source

Requires Rust `1.89+` (2024 edition).

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

## Hostile-Evidence Hardening & Supply Chain

Informed by public forensic-parser vulnerability disclosures (such as Signal's April 2021 analysis of commercial extraction tools), all untrusted parsing in `android2rust` is engineered defensively:

- **`#![forbid(unsafe_code)]` Core & Tooling**: Compiled with `#![forbid(unsafe_code)]` across `core`, `runner`, `report`, `mcp`, `cli`, and `iced` (`unsafe` isolated solely to the Windows Win32 windowing wrapper).
- **Streaming Dual Digests & Decompression-Bomb Caps**: Hashes arbitrarily large artifacts in `64 KiB` chunks for dual **SHA-256 + SHA-512** custody while capping in-memory artifact reads (`256 MiB`), `.ab` zlib inflation (`128 MiB`), `bugreport` text (`64 MiB`), and ZIP entry inflation (`32 MiB`).
- **Tamper & Anomaly Detection**: Flags Zip-Slip (`..`), embedded `NUL` bytes, absolute/drive paths, Unicode BiDi spoofing (`U+202A..202E`, `U+2066..2069`), ZIP Local-vs-Central header mismatches, and Dalvik `dex\n` preambles (`Janus`).
- **Modern Android DFIR**: Parses Android 12+ `ABX\0` binary XML, structured AXML manifest security flags (`debuggable`, `allowBackup`, `usesCleartextTraffic`, `testOnly`, `networkSecurityConfig`, exported component counts), `adb bugreport` ZIPs (`dumpstate`, `usagestats`, `package`, `account`, tombstones/ANRs), `APK Sig Block 42` schemes (`v2`, `v3`, `v3.1`, `SourceStamp-v1`/`v2`), lawful `.ab` PBKDF2-HMAC-SHA1 / AES-256-CBC decryption (`ab_password` skipped from serialization), SQLite `freelist_page_count` / `user_version` / `application_id` + companion `-wal`/`-shm`/`-journal` streams, case provenance (`--case-id`, `--evidence-id`, `--examiner`), CSV formula neutralization (CWE-1236), UTF-16 BOM log ingestion, and chronological CSV/JSONL timelines (`--timeline`).
- **Air-Gapped Report CSP & Binary Mitigations**: Self-contained HTML reports enforce `Content-Security-Policy: default-src 'none'; ...`, Windows `x86_64` MSVC release builds combine `/STACK:16777216`, Control Flow Guard (`-C control-flow-guard=on`), and CET Shadow Stack (`/CETCOMPAT`), and release archives ship `SBOM-crates.txt`.

## License

Licensed under the [Apache License, Version 2.0](LICENSE) (see also [NOTICE](NOTICE)).

Explore the full [**Project Wiki**](https://github.com/adpaolucci/android2rust/wiki) ([WPD/MTP Mobile File Search](https://github.com/adpaolucci/android2rust/wiki/WPD-MTP-Mobile-File-Search), [CLI Reference](https://github.com/adpaolucci/android2rust/wiki/CLI-Reference), [MCP Server Guide](https://github.com/adpaolucci/android2rust/wiki/MCP-Server-Guide)).
