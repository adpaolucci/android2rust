# Changelog

All notable changes to `android2rust` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-22

### Added
- **Modular 7-Crate Pure-Rust Workspace (MSRV `1.89`)**: `android2rust-core`, `android2rust-runner`, `android2rust-report`, `android2rust-mcp`, `android2rust-cli`, `android2rust-win32`, and `android2rust-iced`.
- **ADB, Fastboot & Forensic Job Engine (`android2rust-core`)**: Covers `adb` (devices, props, packages, APK install/uninstall/disable, push/pull, `.ab` backup/restore, logcat, bugreport, dumpsys, sideload, shell, reboot), `fastboot` (devices, getvar, flash, boot, erase, format, unlock/lock, reboot), and pure-Rust offline artifact inspection (`.apk`/ZIP + `AndroidManifest.xml` permissions, `.ab` zlib TAR backup unpacking, SQLite 3 schema/WAL header inspection, `shared_prefs` XML keys, and `getprop`/`logcat` dumps), plus bidirectional CLI & `.a2r` recipe parsers, `.bat`/`.ps1`/`.sh`/`schtasks` exports, status-code decoder, 8 presets, and persistent profiles/history.
- **Hostile-Evidence Parser Hardening & Modern Android DFIR**:
  - Added Android 12+ `ABX\0` binary XML parser (`forensics/abx.rs`), structured binary AXML / plaintext `AndroidManifest.xml` security extraction (`forensics/axml.rs`, including `debuggable`, `allowBackup`, `usesCleartextTraffic`, `testOnly`, `networkSecurityConfig`, and exported component counts), and `adb bugreport` `.zip` inspection (`forensics/bugreport.rs` covering `dumpstate`, `usagestats`, `package`, `account`, tombstones, and ANRs).
  - Added pure-Rust PBKDF2-HMAC-SHA1 / AES-256-CBC decryption for password-protected `.ab` backups (`forensics/ab_crypto.rs`, MSRV `1.89`) with `#[serde(skip)]` passphrase handling (`--password` / `ANDROID2RUST_AB_PASSWORD` / masked GUI passphrase field), plus `APK Sig Block 42` (`v2`/`v3`/`v3.1`/`SourceStamp-v1`/`v2`), SQLite `freelist_page_count`/`user_version`/`application_id`, and companion `-wal`/`-shm`/`-journal` hashing.
  - Added dual `SHA-256` + `SHA-512` chain-of-custody digests, `CaseMetadata` (`--case-id`, `--evidence-id`, `--examiner`), chronological timeline extraction (`report::timeline`, `timeline-csv`, `timeline-jsonl`, and inline HTML/Markdown timeline tables), strict HTML `Content-Security-Policy`, and Windows MSVC release mitigations (`/STACK:16777216`, `-C control-flow-guard=on`, `/CETCOMPAT`, `SBOM-crates.txt`).
- **Live Streaming Runner & Offline Forensic Executor (`android2rust-runner`)**: Discovers `adb` and `fastboot` from `PATH` and Android SDK locations, runs with `CREATE_NO_WINDOW` on Windows, parses device rows, `getprop`, `pm list packages`, transfer `%`, `logcat`, and `fastboot` output in real time, supports non-destructive dry-run simulation and offline forensic execution, and computes dual SHA-256 + SHA-512 chain-of-custody hashes.
- **Air-Gapped Audit Reports (`android2rust-report`)**: Generates standalone offline HTML (with interactive filtering and light/dark toggle), JSON, Markdown, and Timeline CSV/JSONL audit reports from live runs, log files, or raw `.apk`/`.ab`/`.db`/`bugreport.zip` artifacts.
- **Model Context Protocol Server (`android2rust-mcp` & `android2rust mcp`)**: JSON-RPC 2.0 `stdio` MCP server exposing 10 tools (`case_id`/`evidence_id`/`examiner`/`ab_password` support on `dry_run`/`run`, `validate_job` in `report`, `--tools` schema dump) with explicit `confirm_destructive` safety enforcement for destructive ADB and Fastboot operations.
- **Native Win32 Desktop Console (`android2rust-win32`)**: Zero-GPU WinSafe `0.0.29` Win32 Common Controls GUI (ComCtl v6 + Per-Monitor DPI v2 manifest, Vista+ COM dialogs, `run_ui_thread` live stream relay, `MessageBox` destructive confirmation, Case Provenance fields, RAM-only `.ab` passphrase entry, editable Task Scheduler `/D` weekdays, and JSON/Markdown/Timeline report exports).
- **Cross-Platform Iced Desktop Console (`android2rust-iced`)**: Retained-mode Iced `0.14` (`wgpu` + `tiny-skia` CPU fallback) desktop console shipping across Linux, macOS, and Windows (`android2rust gui --iced`), featuring Light/Dark mode, full ADB/Fastboot/Forensic tabs, Case Provenance, `TransportId (-t)` support, `RunOfflineInspectionNow`, live stream, batch queue, run history, and modal overlays.
- **CLI Suite & Packaging (`android2rust`)**: 12 CLI subcommands (`--password` on `dry-run`/`run`, `--case-id`/`--evidence-id`/`--examiner`, bounded `.a2r` reads, `mcp --tools`) with two-stage `Ctrl+C` cancellation, cross-platform GitHub Actions CI/Release workflows, and WinGet / Homebrew packaging manifests.

### Fixed
- Eliminated potential UTF-8 slice-boundary panics in SQLite `scan_sqlite_schema_tables`, `bugreport.rs::normalize_space_ts_to_iso`, and `parse_logcat_timestamp`.
- Escaped `%VAR%` and shell metacharacters cleanly in generated `.bat` scripts (`build_batch_script`).
- Fixed `AndroidOutputParser` ordering so `adb.exe:`/`fastboot.exe:` errors and logcat lines are never misclassified as connected devices.
- Fixed `ProfileStore` error propagation (never overwriting unreadable/corrupted `profiles.json`/`history.json`) and non-ASCII profile slug collisions, runner error code attribution (`exit_code = 1` for forensic failures; cancellation priority over status tokens), bounded live stream/log buffers, CSV formula neutralization (CWE-1236), Markdown backtick escaping, UTF-16 BOM log parsing, and local vs. UTC timestamp preservation.
- Populated `v0.1.0` SHA-256 digests in WinGet and Homebrew packaging manifests.
