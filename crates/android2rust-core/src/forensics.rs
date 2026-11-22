mod ab_crypto;
mod abx;
mod axml;
mod bugreport;

use crate::format::{encode_hex_lower, format_bytes};
use crate::model::ForensicOptions;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate};
use flate2::read::{DeflateDecoder, ZlibDecoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeSet;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    ApkPackage,
    AndroidBackupAb,
    SqliteDatabase,
    XmlManifestOrPrefs,
    AndroidBinaryXml,
    BugreportZip,
    LogOrPropertyDump,
    DirectoryExtraction,
    UnknownBinary,
}

impl ArtifactKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApkPackage => "Android APK / ZIP Archive",
            Self::AndroidBackupAb => "Android Backup (.ab)",
            Self::SqliteDatabase => "SQLite 3 Database",
            Self::XmlManifestOrPrefs => "Android XML (Manifest / SharedPreferences)",
            Self::AndroidBinaryXml => "Android Binary XML (ABX)",
            Self::BugreportZip => "Android Bugreport Archive (.zip)",
            Self::LogOrPropertyDump => "Android Logcat / Getprop Text",
            Self::DirectoryExtraction => "Extracted Android Directory Tree",
            Self::UnknownBinary => "Binary Artifact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicEntry {
    pub category: String,
    pub name: String,
    pub detail: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub source: String,
    pub category: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicReport {
    pub path: String,
    pub kind: ArtifactKind,
    pub total_bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub sha512: String,
    pub metadata: Vec<(String, String)>,
    pub permissions_or_tables: Vec<String>,
    pub entries: Vec<ForensicEntry>,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub timeline: Vec<TimelineEvent>,
}

/// Hard cap on in-memory artifact buffering (`256 MiB`) while streaming full SHA-256 + SHA-512 over the file.
pub const MAX_ARTIFACT_READ_BYTES: u64 = 256 * 1024 * 1024;
/// Hard cap on `.ab` zlib payload decompression (`128 MiB`) to defeat decompression bombs.
pub const MAX_AB_DECOMPRESS_BYTES: usize = 128 * 1024 * 1024;
/// Hard cap on individual APK/ZIP entry decompression (`32 MiB`) for manifest/signature inspection.
pub const MAX_ZIP_ENTRY_DECOMPRESS_BYTES: usize = 32 * 1024 * 1024;

pub(super) fn epoch_ms_to_rfc3339(ms: i64) -> Option<String> {
    if !(1_262_304_000_000..=2_524_608_000_000).contains(&ms) {
        return None;
    }
    DateTime::from_timestamp_millis(ms).map(|dt| dt.to_rfc3339())
}

pub(super) fn dos_datetime_to_rfc3339(date: u16, time: u16) -> Option<String> {
    if date == 0 {
        return None;
    }
    let year = 1980 + i32::from((date >> 9) & 0x7f);
    let month = u32::from((date >> 5) & 0x0f);
    let day = u32::from(date & 0x1f);
    let hour = u32::from((time >> 11) & 0x1f);
    let min = u32::from((time >> 5) & 0x3f);
    let sec = u32::from((time & 0x1f) * 2).min(59);
    let dt = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
    Some(dt.and_utc().to_rfc3339())
}

fn read_artifact_streaming(path: &Path, compute_hashes: bool) -> Result<(Vec<u8>, u64, String, String, bool)> {
    let mut file = std::fs::File::open(path).with_context(|| format!("Failed to open artifact {}", path.display()))?;
    let cap = usize::try_from(MAX_ARTIFACT_READ_BYTES).unwrap_or(usize::MAX);
    let mut buf = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut truncated = false;
    let mut h256 = compute_hashes.then(Sha256::new);
    let mut h512 = compute_hashes.then(Sha512::new);
    let mut chunk = [0u8; 65_536];

    loop {
        match std::io::Read::read(&mut file, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                total_bytes = total_bytes.saturating_add(n as u64);
                if let Some(h) = h256.as_mut() {
                    h.update(&chunk[..n]);
                }
                if let Some(h) = h512.as_mut() {
                    h.update(&chunk[..n]);
                }
                let remaining = cap.saturating_sub(buf.len());
                if remaining > 0 {
                    let take = n.min(remaining);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).with_context(|| format!("Failed to read artifact {}", path.display())),
        }
    }

    let sha256 = h256.map(|h| encode_hex_lower(&h.finalize())).unwrap_or_default();
    let sha512 = h512.map(|h| encode_hex_lower(&h.finalize())).unwrap_or_default();
    Ok((buf, total_bytes, sha256, sha512, truncated))
}

fn read_bounded<R: std::io::Read>(mut reader: R, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 16_384];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok((out, false)),
            Ok(n) => {
                let remaining = limit.saturating_sub(out.len());
                if n > remaining {
                    out.extend_from_slice(&chunk[..remaining]);
                    return Ok((out, true));
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn detect_suspicious_entry_name(name: &str) -> Option<&'static str> {
    if name.contains('\0') {
        return Some("contains embedded NUL byte");
    }
    if name
        .chars()
        .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
    {
        return Some("contains Unicode BiDi override/isolate control character");
    }
    let b = name.as_bytes();
    if name.starts_with('/') || name.starts_with('\\') || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':') {
        return Some("uses absolute or drive-qualified path");
    }
    if name.split(['/', '\\']).any(|seg| seg == "..") {
        return Some("contains parent-directory traversal ('..')");
    }
    None
}

pub fn inspect_artifact(path: &Path, opts: &ForensicOptions) -> Result<ForensicReport> {
    if path.is_dir() {
        let mut rep = inspect_directory(path, opts)?;
        prepend_case_metadata(&mut rep.metadata, &opts.case_meta);
        return Ok(rep);
    }

    let (bytes, total_bytes, sha256, sha512, truncated) = read_artifact_streaming(path, opts.compute_sha256)?;

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut report = if bytes.starts_with(b"ANDROID BACKUP\n") || bytes.starts_with(b"ANDROID BACKUP\r\n") {
        inspect_ab_bytes(path, &bytes, sha256, sha512, opts)
    } else if bytes.starts_with(b"SQLite format 3\0") {
        inspect_sqlite_bytes(path, &bytes, sha256, sha512, opts)
    } else if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || ((bytes.starts_with(b"dex\n") || matches!(ext.as_str(), "apk" | "zip" | "xapk" | "apks"))
            && parse_zip_central_directory(&bytes).is_some())
    {
        inspect_apk_zip_bytes(path, &bytes, sha256, sha512, opts)
    } else if bytes.starts_with(b"ABX\0") {
        abx::inspect_abx_bytes(path, &bytes, sha256, sha512, opts)
    } else if ext == "xml" || looks_like_xml(&bytes) {
        inspect_xml_bytes(path, &bytes, sha256, sha512, opts)
    } else if bytes
        .iter()
        .take(4096)
        .all(|b| !b.is_ascii_control() || matches!(b, b'\n' | b'\r' | b'\t'))
    {
        inspect_text_dump_bytes(path, &bytes, sha256, sha512, opts)
    } else {
        ForensicReport {
            path: path.display().to_string(),
            kind: ArtifactKind::UnknownBinary,
            total_bytes,
            sha256,
            sha512,
            metadata: vec![("Format".to_string(), "Unrecognized binary blob".to_string())],
            permissions_or_tables: Vec::new(),
            entries: Vec::new(),
            warnings: vec![
                "Magic bytes did not match APK/ZIP, ABX, .ab backup, SQLite 3, XML, or UTF-8 text.".to_string(),
            ],
            timeline: Vec::new(),
        }
    };

    report.total_bytes = total_bytes;
    if truncated {
        report.warnings.push(format!(
            "Artifact exceeds {} MiB in-memory inspection cap ({} total bytes); SHA-256 and SHA-512 hash the entire file while structural parsing inspected only the leading prefix.",
            MAX_ARTIFACT_READ_BYTES / (1024 * 1024),
            total_bytes
        ));
    }
    prepend_case_metadata(&mut report.metadata, &opts.case_meta);
    report.timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    report.entries.truncate(opts.max_entries.max(1));
    Ok(report)
}

fn prepend_case_metadata(metadata: &mut Vec<(String, String)>, case_meta: &crate::model::CaseMetadata) {
    let mut prefix = Vec::new();
    if let Some(cid) = case_meta.case_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        prefix.push(("Case ID".to_string(), cid.to_string()));
    }
    if let Some(eid) = case_meta
        .evidence_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        prefix.push(("Evidence ID".to_string(), eid.to_string()));
    }
    if let Some(ex) = case_meta.examiner.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        prefix.push(("Examiner".to_string(), ex.to_string()));
    }
    if !prefix.is_empty() {
        prefix.append(metadata);
        *metadata = prefix;
    }
}

fn inspect_directory(dir: &Path, opts: &ForensicOptions) -> Result<ForensicReport> {
    let mut entries = Vec::new();
    let mut total_bytes = 0u64;
    let mut total_files = 0usize;
    let mut apk_count = 0usize;
    let mut db_count = 0usize;
    let mut xml_count = 0usize;
    let mut ab_count = 0usize;

    for entry in WalkDir::new(dir).follow_links(false).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            total_files += 1;
            let meta = entry.metadata().ok();
            let sz = meta.map(|m| m.len()).unwrap_or(0);
            total_bytes += sz;
            let rel = entry
                .path()
                .strip_prefix(dir)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            let lower = rel.to_ascii_lowercase();
            let cat = if lower.ends_with(".apk") {
                apk_count += 1;
                "APK"
            } else if lower.ends_with(".db") || lower.ends_with(".sqlite") || lower.ends_with(".sqlite3") {
                db_count += 1;
                "SQLite DB"
            } else if lower.ends_with(".ab") {
                ab_count += 1;
                "Android Backup"
            } else if lower.ends_with(".xml") {
                xml_count += 1;
                "XML"
            } else {
                "File"
            };
            if entries.len() < opts.max_entries {
                entries.push(ForensicEntry {
                    category: cat.to_string(),
                    name: rel,
                    detail: format_bytes(sz),
                    size_bytes: Some(sz),
                });
            }
        }
    }

    Ok(ForensicReport {
        path: dir.display().to_string(),
        kind: ArtifactKind::DirectoryExtraction,
        total_bytes,
        sha256: "directory-tree".to_string(),
        sha512: "directory-tree".to_string(),
        metadata: vec![
            ("Files Scanned".to_string(), total_files.to_string()),
            ("APK Files".to_string(), apk_count.to_string()),
            ("SQLite DBs".to_string(), db_count.to_string()),
            ("XML Files".to_string(), xml_count.to_string()),
            ("Backup (.ab) Files".to_string(), ab_count.to_string()),
        ],
        permissions_or_tables: Vec::new(),
        entries,
        warnings: Vec::new(),
        timeline: Vec::new(),
    })
}

fn inspect_ab_bytes(
    path: &Path,
    bytes: &[u8],
    sha256: String,
    sha512: String,
    opts: &ForensicOptions,
) -> ForensicReport {
    let mut metadata = Vec::new();
    let mut warnings = Vec::new();
    let mut entries = Vec::new();
    let mut permissions_or_tables = Vec::new();
    let mut timeline = Vec::new();

    // Parse 4-line header: ANDROID BACKUP \n version \n compressed \n encryption \n
    let mut pos = 0usize;
    let mut lines = Vec::new();
    for _ in 0..4 {
        if let Some(nl) = bytes[pos..].iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&bytes[pos..pos + nl]).trim().to_string();
            lines.push(line);
            pos += nl + 1;
        } else {
            break;
        }
    }

    let version = lines.get(1).cloned().unwrap_or_else(|| "?".to_string());
    let compressed = lines.get(2).map(|s| s == "1").unwrap_or(false);
    let encryption = lines.get(3).cloned().unwrap_or_else(|| "unknown".to_string());

    metadata.push(("Format Version".to_string(), version.clone()));
    metadata.push(("Compressed (zlib)".to_string(), compressed.to_string()));
    metadata.push(("Encryption".to_string(), encryption.clone()));

    if !encryption.eq_ignore_ascii_case("none") {
        match ab_crypto::parse_ab_encryption_header(bytes, pos) {
            Ok(enc_hdr) => {
                metadata.push(("PBKDF2 Rounds".to_string(), enc_hdr.rounds.to_string()));
                metadata.push((
                    "User Salt".to_string(),
                    format!(
                        "{} ({} B)",
                        encode_hex_lower(&enc_hdr.user_salt[..enc_hdr.user_salt.len().min(8)]),
                        enc_hdr.user_salt.len()
                    ),
                ));
                metadata.push(("User IV".to_string(), encode_hex_lower(&enc_hdr.user_iv)));

                if let Some(pw) = opts.ab_password.as_deref().filter(|p| !p.is_empty()) {
                    let cap = usize::try_from(MAX_ARTIFACT_READ_BYTES).unwrap_or(usize::MAX);
                    match ab_crypto::decrypt_ab_payload(&version, &enc_hdr, &bytes[enc_hdr.payload_offset..], pw, cap) {
                        Ok(plain) => {
                            metadata.push(("Decryption Status".to_string(), "Verified & Decrypted".to_string()));
                            if opts.inspect_ab_tar_entries {
                                process_ab_tar_payload(
                                    &plain,
                                    compressed,
                                    opts,
                                    &mut metadata,
                                    &mut warnings,
                                    &mut entries,
                                    &mut permissions_or_tables,
                                    &mut timeline,
                                );
                            }
                        }
                        Err(err) => {
                            metadata.push(("Decryption Status".to_string(), "Failed".to_string()));
                            warnings.push(err);
                        }
                    }
                } else {
                    warnings.push(format!(
                        "Android backup payload is encrypted ('{encryption}', {} PBKDF2 rounds). Pass --password or ANDROID2RUST_AB_PASSWORD for lawful inspection.",
                        enc_hdr.rounds
                    ));
                }
            }
            Err(err) => {
                warnings.push(format!("Android backup payload is encrypted ('{encryption}'): {err}"));
            }
        }
    } else if opts.inspect_ab_tar_entries {
        process_ab_tar_payload(
            &bytes[pos..],
            compressed,
            opts,
            &mut metadata,
            &mut warnings,
            &mut entries,
            &mut permissions_or_tables,
            &mut timeline,
        );
    }

    ForensicReport {
        path: path.display().to_string(),
        kind: ArtifactKind::AndroidBackupAb,
        total_bytes: bytes.len() as u64,
        sha256,
        sha512,
        metadata,
        permissions_or_tables,
        entries,
        warnings,
        timeline,
    }
}

#[allow(clippy::too_many_arguments)]
fn process_ab_tar_payload(
    payload: &[u8],
    compressed: bool,
    opts: &ForensicOptions,
    metadata: &mut Vec<(String, String)>,
    warnings: &mut Vec<String>,
    entries: &mut Vec<ForensicEntry>,
    permissions_or_tables: &mut Vec<String>,
    timeline: &mut Vec<TimelineEvent>,
) {
    let tar_bytes_res: Result<(Vec<u8>, bool), std::io::Error> = if compressed {
        read_bounded(ZlibDecoder::new(payload), MAX_AB_DECOMPRESS_BYTES)
    } else {
        let truncated = payload.len() > MAX_AB_DECOMPRESS_BYTES;
        let take = payload.len().min(MAX_AB_DECOMPRESS_BYTES);
        Ok((payload[..take].to_vec(), truncated))
    };

    match tar_bytes_res {
        Ok((tar_bytes, ab_truncated)) => {
            metadata.push(("TAR Payload Size".to_string(), format_bytes(tar_bytes.len() as u64)));
            if ab_truncated {
                warnings.push(format!(
                    ".ab TAR payload exceeded {} MiB decompression limit (possible decompression bomb); inspected truncated prefix.",
                    MAX_AB_DECOMPRESS_BYTES / (1024 * 1024)
                ));
            }
            let (tar_entries, nested, tar_warnings, tar_timeline) = parse_tar_headers(&tar_bytes, opts);
            metadata.push(("TAR Entries Discovered".to_string(), tar_entries.len().to_string()));
            *entries = tar_entries;
            *permissions_or_tables = nested;
            warnings.extend(tar_warnings);
            timeline.extend(tar_timeline);
        }
        Err(err) => {
            warnings.push(format!("Failed to inflate .ab zlib stream: {err}"));
        }
    }
}

fn parse_tar_headers(
    data: &[u8],
    opts: &ForensicOptions,
) -> (Vec<ForensicEntry>, Vec<String>, Vec<String>, Vec<TimelineEvent>) {
    const MAX_NESTED_INSPECT_BYTES: u64 = 32 * 1024 * 1024;
    let mut out = Vec::new();
    let mut nested = BTreeSet::new();
    let mut tar_warnings = Vec::new();
    let mut timeline = Vec::new();
    let mut suspicious_count = 0usize;
    let mut offset = 0usize;

    while offset + 512 <= data.len() && out.len() < opts.max_entries {
        let header = &data[offset..offset + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name = read_c_string(&header[0..100]);
        let prefix = read_c_string(&header[345..500]);
        let full_name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let size_str = read_c_string(&header[124..136]);
        let size = u64::from_str_radix(size_str.trim(), 8).unwrap_or(0);
        let mtime_str = read_c_string(&header[136..148]);
        let mtime_secs = i64::from_str_radix(mtime_str.trim(), 8).unwrap_or(0);
        let typeflag = header[156];
        let kind = match typeflag {
            b'5' => "TAR Dir",
            b'2' => "TAR Symlink",
            _ => "TAR File",
        };

        if !full_name.is_empty()
            && let Some(reason) = detect_suspicious_entry_name(&full_name)
        {
            suspicious_count += 1;
            if tar_warnings.len() < 5 {
                tar_warnings.push(format!(
                    "Suspicious TAR entry path '{}' ({reason}).",
                    full_name.escape_default()
                ));
            }
        }
        if typeflag == b'2' {
            let link_target = read_c_string(&header[157..257]);
            if !link_target.is_empty()
                && let Some(reason) = detect_suspicious_entry_name(&link_target)
            {
                suspicious_count += 1;
                if tar_warnings.len() < 5 {
                    tar_warnings.push(format!(
                        "Suspicious TAR symlink target '{}' -> '{}' ({reason}).",
                        full_name.escape_default(),
                        link_target.escape_default()
                    ));
                }
            }
        }

        let mut detail = format_bytes(size);
        let payload_start = offset + 512;
        if !matches!(typeflag, b'5' | b'2')
            && size > 0
            && size <= MAX_NESTED_INSPECT_BYTES
            && let Ok(plen) = usize::try_from(size)
            && let Some(payload_end) = payload_start.checked_add(plen)
            && payload_end <= data.len()
        {
            let file_bytes = &data[payload_start..payload_end];
            if opts.inspect_sqlite_tables && file_bytes.starts_with(b"SQLite format 3\0") {
                let (wal_mode, tables, _) = scan_sqlite_schema_tables(file_bytes);
                for tbl in tables {
                    nested.insert(tbl);
                }
                detail = if wal_mode {
                    format!("{detail} [SQLite 3, WAL]")
                } else {
                    format!("{detail} [SQLite 3]")
                };
            } else if opts.extract_manifest_permissions
                && (full_name == "AndroidManifest.xml" || full_name.ends_with("/AndroidManifest.xml"))
            {
                let sec = axml::parse_manifest_security(file_bytes);
                let mut perms = scan_android_permissions(file_bytes);
                perms.extend(sec.permissions);
                let count = perms.len();
                nested.extend(perms);
                detail = format!("{detail} [{count} permissions]");
            }
        }

        if !full_name.is_empty() {
            if mtime_secs > 0
                && mtime_secs < 4_102_444_800
                && timeline.len() < opts.max_entries
                && let Some(dt) = DateTime::from_timestamp(mtime_secs, 0)
            {
                timeline.push(TimelineEvent {
                    timestamp: dt.to_rfc3339(),
                    source: "TAR mtime".to_string(),
                    category: if typeflag == b'5' {
                        "Dir Modified".to_string()
                    } else {
                        "File Modified".to_string()
                    },
                    target: full_name.clone(),
                    detail: detail.clone(),
                });
            }
            out.push(ForensicEntry {
                category: kind.to_string(),
                name: full_name,
                detail,
                size_bytes: Some(size),
            });
        }

        let data_blocks = size.div_ceil(512) as usize;
        offset = offset
            .saturating_add(512)
            .saturating_add(data_blocks.saturating_mul(512));
    }

    if suspicious_count > 5 {
        tar_warnings.push(format!(
            "...and {} additional suspicious TAR entry paths detected.",
            suspicious_count - 5
        ));
    }

    (out, nested.into_iter().collect(), tar_warnings, timeline)
}

fn read_c_string(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).trim().to_string()
}

fn inspect_apk_zip_bytes(
    path: &Path,
    bytes: &[u8],
    sha256: String,
    sha512: String,
    opts: &ForensicOptions,
) -> ForensicReport {
    let mut entries = Vec::new();
    let mut permissions = BTreeSet::new();
    let mut warnings = Vec::new();
    let mut timeline = Vec::new();
    let mut dex_count = 0usize;
    let mut so_abis = BTreeSet::new();
    let mut has_manifest = false;
    let mut has_sig = false;

    let (zip_entries, cd_offset_opt) = match parse_zip_central_directory(bytes) {
        Some((entries_cd, cd_off)) => (entries_cd, Some(cd_off)),
        None => (parse_zip_local_headers(bytes), None),
    };

    if bytes.starts_with(b"dex\n") {
        warnings.push(
            "Archive begins with Dalvik DEX magic ('dex\\n') before ZIP Local File Headers — possible Janus (CVE-2017-13156) polyglot APK."
                .to_string(),
        );
    } else if let Some(first_off) = zip_entries.iter().map(|z| z.local_header_offset).min()
        && first_off > 0
    {
        warnings.push(format!(
            "ZIP/APK contains {first_off} preamble bytes before first Local File Header (potential polyglot / Janus anomaly)."
        ));
    }

    let mut suspicious_count = 0usize;
    let mut mismatch_count = 0usize;
    let mut mismatch_warnings = Vec::new();

    for ze in &zip_entries {
        if let Some(reason) = detect_suspicious_entry_name(&ze.name) {
            suspicious_count += 1;
            if suspicious_count <= 5 {
                warnings.push(format!(
                    "Suspicious ZIP/APK entry path '{}' ({reason}).",
                    ze.name.escape_default()
                ));
            }
        }
        if cd_offset_opt.is_some()
            && let Some(msg) = check_zip_local_vs_central(bytes, ze)
        {
            mismatch_count += 1;
            if mismatch_warnings.len() < 5 {
                mismatch_warnings.push(msg);
            }
        }
        if ze.name == "AndroidManifest.xml" {
            has_manifest = true;
        }
    }

    if suspicious_count > 5 {
        warnings.push(format!(
            "...and additional suspicious ZIP/APK entry paths detected ({suspicious_count} total)."
        ));
    }
    warnings.extend(mismatch_warnings);
    if mismatch_count > 5 {
        warnings.push(format!(
            "...and {} additional ZIP Local-vs-Central header mismatches detected.",
            mismatch_count - 5
        ));
    }

    // Dispatch to dedicated adb bugreport ZIP inspector if applicable
    if bugreport::is_bugreport_zip(&zip_entries, has_manifest) {
        return bugreport::inspect_bugreport_zip_bytes(path, bytes, sha256, sha512, &zip_entries, warnings, opts);
    }

    let mut manifest_meta = Vec::new();
    let mut timeline_cap = opts.max_entries.min(500);

    for ze in &zip_entries {
        let lower = ze.name.to_ascii_lowercase();
        let cat = if ze.name == "AndroidManifest.xml" {
            "Manifest"
        } else if lower.starts_with("classes") && lower.ends_with(".dex") {
            dex_count += 1;
            "DEX Bytecode"
        } else if lower.starts_with("lib/") && lower.ends_with(".so") {
            if let Some(abi) = ze.name.split('/').nth(1) {
                so_abis.insert(abi.to_string());
            }
            "Native Library"
        } else if lower.starts_with("meta-inf/")
            && (lower.ends_with(".rsa") || lower.ends_with(".ec") || lower.ends_with(".dsa") || lower.ends_with(".sf"))
        {
            has_sig = true;
            "Signature"
        } else if lower.ends_with(".arsc") {
            "Resources"
        } else {
            "Archive Entry"
        };

        let sz = u64::from(ze.uncompressed_size);
        let detail = format!("{} (method {})", format_bytes(sz), ze.method);
        if entries.len() < opts.max_entries {
            entries.push(ForensicEntry {
                category: cat.to_string(),
                name: ze.name.clone(),
                detail: detail.clone(),
                size_bytes: Some(sz),
            });
        }
        if timeline_cap > 0
            && matches!(
                cat,
                "Manifest" | "DEX Bytecode" | "Native Library" | "Signature" | "Resources"
            )
            && let Some(ts) = dos_datetime_to_rfc3339(ze.mod_date, ze.mod_time)
        {
            timeline.push(TimelineEvent {
                timestamp: ts,
                source: "APK/ZIP DOS".to_string(),
                category: format!("{cat} Modified"),
                target: ze.name.clone(),
                detail,
            });
            timeline_cap -= 1;
        }

        if ze.name == "AndroidManifest.xml" {
            if let Some((manifest_bytes, truncated)) = extract_zip_entry_bytes(bytes, ze) {
                if truncated {
                    warnings.push(format!(
                        "AndroidManifest.xml exceeded {} MiB decompression limit (possible ZIP decompression bomb); inspected truncated prefix.",
                        MAX_ZIP_ENTRY_DECOMPRESS_BYTES / (1024 * 1024)
                    ));
                }
                let sec = axml::parse_manifest_security(&manifest_bytes);
                axml::append_manifest_security(&sec, &mut manifest_meta, &mut warnings);
                if opts.extract_manifest_permissions {
                    permissions.extend(sec.permissions);
                    for perm in scan_android_permissions(&manifest_bytes) {
                        permissions.insert(perm);
                    }
                }
            } else {
                warnings
                    .push("Could not decompress AndroidManifest.xml (unsupported or corrupt ZIP entry).".to_string());
            }
        }
    }

    let mut sig_schemes: Vec<String> = Vec::new();
    if has_sig {
        sig_schemes.push("v1".to_string());
    }
    if let Some(cd_off) = cd_offset_opt {
        for scheme in parse_apk_signing_block(bytes, cd_off) {
            sig_schemes.push(scheme.to_string());
        }
    }

    if !has_manifest {
        warnings.push(
            "Archive does not contain AndroidManifest.xml (may be a generic ZIP or split resource pack).".to_string(),
        );
    }
    if has_manifest && sig_schemes.is_empty() {
        warnings
            .push("No v1 META-INF or v2/v3 APK Signing Block signatures found (unsigned or stripped APK).".to_string());
    }

    let sig_summary = if sig_schemes.is_empty() {
        "None detected".to_string()
    } else {
        sig_schemes.join(", ")
    };

    let abis_str = if so_abis.is_empty() {
        "Pure Java/Kotlin (no native .so)".to_string()
    } else {
        so_abis.into_iter().collect::<Vec<_>>().join(", ")
    };

    let mut metadata = vec![
        ("ZIP Entries".to_string(), zip_entries.len().to_string()),
        ("DEX Files".to_string(), dex_count.to_string()),
        ("Native ABIs".to_string(), abis_str),
        ("Manifest Present".to_string(), has_manifest.to_string()),
        ("Signature Schemes".to_string(), sig_summary),
        ("Permissions Found".to_string(), permissions.len().to_string()),
    ];
    metadata.extend(manifest_meta);

    ForensicReport {
        path: path.display().to_string(),
        kind: ArtifactKind::ApkPackage,
        total_bytes: bytes.len() as u64,
        sha256,
        sha512,
        metadata,
        permissions_or_tables: permissions.into_iter().collect(),
        entries,
        warnings,
        timeline,
    }
}

pub(super) struct ZipEntryMeta {
    pub name: String,
    pub method: u16,
    pub mod_time: u16,
    pub mod_date: u16,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_header_offset: usize,
}

fn parse_zip_central_directory(bytes: &[u8]) -> Option<(Vec<ZipEntryMeta>, usize)> {
    // Locate EOCD PK\x05\x06 within last 66KB
    let min_pos = bytes.len().saturating_sub(65_557);
    let mut eocd_pos = None;
    for i in (min_pos..=bytes.len().saturating_sub(22)).rev() {
        if &bytes[i..i + 4] == b"PK\x05\x06" {
            eocd_pos = Some(i);
            break;
        }
    }
    let eocd = eocd_pos?;
    let total_entries = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
    let cd_offset =
        u32::from_le_bytes([bytes[eocd + 16], bytes[eocd + 17], bytes[eocd + 18], bytes[eocd + 19]]) as usize;

    if cd_offset > eocd || (total_entries > 0 && bytes.get(cd_offset..cd_offset + 4) != Some(b"PK\x01\x02".as_slice()))
    {
        return None;
    }

    let mut pos = cd_offset;
    let mut out = Vec::with_capacity(total_entries.min(4096));
    while pos + 46 <= bytes.len() && &bytes[pos..pos + 4] == b"PK\x01\x02" {
        let method = u16::from_le_bytes([bytes[pos + 10], bytes[pos + 11]]);
        let mod_time = u16::from_le_bytes([bytes[pos + 12], bytes[pos + 13]]);
        let mod_date = u16::from_le_bytes([bytes[pos + 14], bytes[pos + 15]]);
        let compressed_size = u32::from_le_bytes([bytes[pos + 20], bytes[pos + 21], bytes[pos + 22], bytes[pos + 23]]);
        let uncompressed_size =
            u32::from_le_bytes([bytes[pos + 24], bytes[pos + 25], bytes[pos + 26], bytes[pos + 27]]);
        let name_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[pos + 30], bytes[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[pos + 32], bytes[pos + 33]]) as usize;
        let local_offset =
            u32::from_le_bytes([bytes[pos + 42], bytes[pos + 43], bytes[pos + 44], bytes[pos + 45]]) as usize;

        if pos + 46 + name_len > bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[pos + 46..pos + 46 + name_len]).into_owned();
        out.push(ZipEntryMeta {
            name,
            method,
            mod_time,
            mod_date,
            compressed_size,
            uncompressed_size,
            local_header_offset: local_offset,
        });
        pos = pos
            .saturating_add(46)
            .saturating_add(name_len)
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }
    Some((out, cd_offset))
}

fn parse_apk_signing_block(bytes: &[u8], cd_offset: usize) -> Vec<&'static str> {
    if cd_offset < 32 || cd_offset > bytes.len() {
        return Vec::new();
    }
    if &bytes[cd_offset - 16..cd_offset] != b"APK Sig Block 42" {
        return Vec::new();
    }
    let footer_size = u64::from_le_bytes(bytes[cd_offset - 24..cd_offset - 16].try_into().unwrap_or([0; 8]));
    let Ok(footer_usize) = usize::try_from(footer_size) else {
        return Vec::new();
    };
    if footer_usize < 24 || footer_usize > cd_offset.saturating_sub(8) {
        return Vec::new();
    }
    let block_start = cd_offset - footer_usize - 8;
    let header_size = u64::from_le_bytes(bytes[block_start..block_start + 8].try_into().unwrap_or([0; 8]));
    if header_size != footer_size {
        return Vec::new();
    }

    let mut pos = block_start + 8;
    let pairs_end = cd_offset - 24;
    let mut schemes = Vec::new();
    while pos + 12 <= pairs_end {
        let pair_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap_or([0; 8]));
        let Ok(pair_usize) = usize::try_from(pair_len) else {
            break;
        };
        if pair_usize < 4 {
            break;
        }
        let Some(next) = pos.checked_add(8).and_then(|p| p.checked_add(pair_usize)) else {
            break;
        };
        if next > pairs_end {
            break;
        }
        let id = u32::from_le_bytes(bytes[pos + 8..pos + 12].try_into().unwrap_or([0; 4]));
        let label = match id {
            0x7109_871a => Some("v2"),
            0xf053_68c0 => Some("v3"),
            0x1b93_ad61 => Some("v3.1"),
            0x4272_6577 => Some("SourceStamp-v1"),
            0x6dff_800d => Some("SourceStamp-v2"),
            _ => None,
        };
        if let Some(name) = label
            && !schemes.contains(&name)
        {
            schemes.push(name);
        }
        pos = next;
    }
    schemes
}

fn check_zip_local_vs_central(bytes: &[u8], ze: &ZipEntryMeta) -> Option<String> {
    let off = ze.local_header_offset;
    let Some(hdr) = bytes.get(off..off.saturating_add(30)) else {
        return Some(format!(
            "ZIP Central Directory entry '{}' references out-of-bounds Local Header at offset {off}.",
            ze.name.escape_default()
        ));
    };
    if &hdr[0..4] != b"PK\x03\x04" {
        return Some(format!(
            "ZIP Central Directory entry '{}' points to non-PK\\x03\\x04 Local Header at offset {off}.",
            ze.name.escape_default()
        ));
    }
    let local_flags = u16::from_le_bytes([hdr[6], hdr[7]]);
    let local_method = u16::from_le_bytes([hdr[8], hdr[9]]);
    let local_comp = u32::from_le_bytes([hdr[18], hdr[19], hdr[20], hdr[21]]);
    let local_uncomp = u32::from_le_bytes([hdr[22], hdr[23], hdr[24], hdr[25]]);
    let local_name_len = u16::from_le_bytes([hdr[26], hdr[27]]) as usize;
    let Some(local_name_bytes) = bytes.get(off + 30..off + 30 + local_name_len) else {
        return Some(format!(
            "ZIP Local Header filename for '{}' extends past EOF.",
            ze.name.escape_default()
        ));
    };
    let local_name = String::from_utf8_lossy(local_name_bytes);
    if local_name.as_ref() != ze.name {
        return Some(format!(
            "ZIP Local-vs-Central filename mismatch: Central='{}' vs Local='{}'.",
            ze.name.escape_default(),
            local_name.escape_default()
        ));
    }
    if local_method != ze.method {
        return Some(format!(
            "ZIP Local-vs-Central compression method mismatch for '{}': Central={} vs Local={}.",
            ze.name.escape_default(),
            ze.method,
            local_method
        ));
    }
    if (local_flags & 0x0008) == 0 && (local_comp != ze.compressed_size || local_uncomp != ze.uncompressed_size) {
        return Some(format!(
            "ZIP Local-vs-Central size mismatch for '{}': Central=({}/{}) vs Local=({}/{}).",
            ze.name.escape_default(),
            ze.compressed_size,
            ze.uncompressed_size,
            local_comp,
            local_uncomp
        ));
    }
    None
}

fn parse_zip_local_headers(bytes: &[u8]) -> Vec<ZipEntryMeta> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 30 <= bytes.len() && &bytes[pos..pos + 4] == b"PK\x03\x04" {
        let method = u16::from_le_bytes([bytes[pos + 8], bytes[pos + 9]]);
        let mod_time = u16::from_le_bytes([bytes[pos + 10], bytes[pos + 11]]);
        let mod_date = u16::from_le_bytes([bytes[pos + 12], bytes[pos + 13]]);
        let compressed_size = u32::from_le_bytes([bytes[pos + 18], bytes[pos + 19], bytes[pos + 20], bytes[pos + 21]]);
        let uncompressed_size =
            u32::from_le_bytes([bytes[pos + 22], bytes[pos + 23], bytes[pos + 24], bytes[pos + 25]]);
        let name_len = u16::from_le_bytes([bytes[pos + 26], bytes[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        if pos + 30 + name_len > bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[pos + 30..pos + 30 + name_len]).into_owned();
        out.push(ZipEntryMeta {
            name,
            method,
            mod_time,
            mod_date,
            compressed_size,
            uncompressed_size,
            local_header_offset: pos,
        });
        let step = 30usize
            .saturating_add(name_len)
            .saturating_add(extra_len)
            .saturating_add(compressed_size as usize);
        if step == 0 {
            break;
        }
        pos = pos.saturating_add(step);
    }
    out
}

pub(super) fn extract_zip_entry_bytes_with_cap(
    archive: &[u8],
    meta: &ZipEntryMeta,
    max_bytes: usize,
) -> Option<(Vec<u8>, bool)> {
    let off = meta.local_header_offset;
    let hdr = archive.get(off..off.checked_add(30)?)?;
    if &hdr[0..4] != b"PK\x03\x04" {
        return None;
    }
    let name_len = u16::from_le_bytes([hdr[26], hdr[27]]) as usize;
    let extra_len = u16::from_le_bytes([hdr[28], hdr[29]]) as usize;
    let data_start = off.checked_add(30)?.checked_add(name_len)?.checked_add(extra_len)?;
    let data_end = data_start.checked_add(meta.compressed_size as usize)?;
    let slice = archive.get(data_start..data_end)?;
    match meta.method {
        0 => {
            let truncated = slice.len() > max_bytes;
            let take = slice.len().min(max_bytes);
            Some((slice[..take].to_vec(), truncated))
        }
        8 => read_bounded(DeflateDecoder::new(slice), max_bytes).ok(),
        _ => None,
    }
}

fn extract_zip_entry_bytes(archive: &[u8], meta: &ZipEntryMeta) -> Option<(Vec<u8>, bool)> {
    extract_zip_entry_bytes_with_cap(archive, meta, MAX_ZIP_ENTRY_DECOMPRESS_BYTES)
}

/// Extracts `android.permission.*` and `uses-permission` strings from binary AXML or plain XML.
fn scan_android_permissions(bytes: &[u8]) -> BTreeSet<String> {
    let mut perms = BTreeSet::new();
    // 1. UTF-8 / ASCII scan
    let ascii = String::from_utf8_lossy(bytes);
    collect_permissions_from_str(&ascii, &mut perms);

    // 2. Binary Android AXML UTF-16LE string pool scan
    if bytes.len() >= 4 {
        let mut units = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.as_chunks::<2>().0 {
            let u = u16::from_le_bytes(*chunk);
            if (0x20..=0x7E).contains(&u) {
                units.push(u as u8);
            } else {
                units.push(b' ');
            }
        }
        let u16_str = String::from_utf8_lossy(&units);
        collect_permissions_from_str(&u16_str, &mut perms);
    }
    perms
}

pub(super) fn collect_permissions_from_str(text: &str, out: &mut BTreeSet<String>) {
    for marker in ["android.permission.", "com.android.permission."] {
        let mut idx = 0usize;
        while let Some(found) = text[idx..].find(marker) {
            let start = idx + found;
            let end = text[start..]
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_')
                .map(|e| start + e)
                .unwrap_or(text.len());
            let candidate = &text[start..end];
            if candidate.len() > marker.len() {
                out.insert(candidate.to_string());
            }
            idx = end.max(start + marker.len());
        }
    }
}

fn inspect_sqlite_companion_files(path: &Path, compute_sha256: bool) -> (Vec<ForensicEntry>, Vec<String>, bool) {
    let mut entries = Vec::new();
    let mut names = Vec::new();
    let mut wal_found = false;

    for suffix in ["-wal", "-shm", "-journal"] {
        let mut companion_os = path.as_os_str().to_os_string();
        companion_os.push(suffix);
        let companion_path = Path::new(&companion_os);
        if !companion_path.is_file() {
            continue;
        }
        let Ok(mut file) = std::fs::File::open(companion_path) else {
            continue;
        };

        let mut comp_len: u64 = 0;
        let mut head = [0u8; 32];
        let mut head_len = 0usize;
        let mut hasher = compute_sha256.then(Sha256::new);
        let mut chunk = [0u8; 65_536];

        loop {
            match std::io::Read::read(&mut file, &mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if head_len < head.len() {
                        let copy_n = n.min(head.len() - head_len);
                        head[head_len..head_len + copy_n].copy_from_slice(&chunk[..copy_n]);
                        head_len += copy_n;
                    }
                    comp_len = comp_len.saturating_add(n as u64);
                    if let Some(h) = hasher.as_mut() {
                        h.update(&chunk[..n]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }

        if suffix == "-wal" {
            wal_found = true;
        }

        let wal_info = if suffix == "-wal" && head_len >= 12 {
            let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
            let wal_page_size = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
            if (magic == 0x377f_0682 || magic == 0x377f_0683) && wal_page_size >= 512 && comp_len >= 32 {
                let frame_bytes = 24u64.saturating_add(u64::from(wal_page_size));
                let frames = (comp_len - 32) / frame_bytes;
                format!(" | WAL {frames} frame(s) ({wal_page_size} B/page)")
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let sha_info = hasher
            .map(|h| format!(" | sha256={}", encode_hex_lower(&h.finalize())))
            .unwrap_or_default();

        let file_label = companion_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(suffix)
            .to_string();

        entries.push(ForensicEntry {
            category: "SQLite Companion".to_string(),
            name: file_label.clone(),
            detail: format!("{}{wal_info}{sha_info}", format_bytes(comp_len)),
            size_bytes: Some(comp_len),
        });
        names.push(file_label);
    }

    (entries, names, wal_found)
}

fn inspect_sqlite_bytes(
    path: &Path,
    bytes: &[u8],
    sha256: String,
    sha512: String,
    opts: &ForensicOptions,
) -> ForensicReport {
    let mut metadata = Vec::new();
    let mut warnings = Vec::new();
    let mut wal_mode = false;

    if bytes.len() >= 100 {
        let raw_page_size = u16::from_be_bytes([bytes[16], bytes[17]]);
        let page_size: u32 = if raw_page_size == 1 {
            65_536
        } else {
            u32::from(raw_page_size)
        };
        let write_ver = bytes[18];
        let read_ver = bytes[19];
        let page_count = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        let freelist_pages = u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let encoding = u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]);
        let user_version = u32::from_be_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]);
        let app_id = u32::from_be_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]);
        let enc_label = match encoding {
            1 => "UTF-8",
            2 => "UTF-16le",
            3 => "UTF-16be",
            _ => "Unknown",
        };
        wal_mode = write_ver == 2 || read_ver == 2;
        metadata.push(("Page Size".to_string(), format!("{page_size} bytes")));
        metadata.push(("Page Count".to_string(), page_count.to_string()));
        metadata.push(("Freelist Pages".to_string(), freelist_pages.to_string()));
        metadata.push(("User Version".to_string(), user_version.to_string()));
        metadata.push(("Application ID".to_string(), format!("0x{app_id:08x}")));
        metadata.push(("WAL Mode".to_string(), wal_mode.to_string()));
        metadata.push(("Text Encoding".to_string(), enc_label.to_string()));
        if freelist_pages > 0 {
            warnings.push(format!(
                "Database contains {freelist_pages} unallocated freelist page(s) — deleted records may still remain recoverable on free pages."
            ));
        }
    }

    let (companion_entries, companion_names, wal_found) = inspect_sqlite_companion_files(path, opts.compute_sha256);
    metadata.push((
        "Companion Files".to_string(),
        if companion_names.is_empty() {
            "None detected".to_string()
        } else {
            companion_names.join(", ")
        },
    ));

    if wal_mode {
        if wal_found {
            warnings.push(
                "Database uses Write-Ahead Logging (WAL); companion -wal detected and recorded — preserve main DB alongside -wal/-shm for complete state."
                    .to_string(),
            );
        } else {
            warnings.push(
                "Database uses Write-Ahead Logging (WAL) and no companion -wal file was found on disk; recent or uncommitted transactions may be absent."
                    .to_string(),
            );
        }
    }

    let mut entries = companion_entries;
    let mut tables = Vec::new();
    if opts.inspect_sqlite_tables {
        let (_, detected_tables, schema_entries) = scan_sqlite_schema_tables(bytes);
        tables = detected_tables;
        entries.extend(schema_entries);
    }

    metadata.push(("Tables Detected".to_string(), tables.len().to_string()));

    ForensicReport {
        path: path.display().to_string(),
        kind: ArtifactKind::SqliteDatabase,
        total_bytes: bytes.len() as u64,
        sha256,
        sha512,
        metadata,
        permissions_or_tables: tables,
        entries,
        warnings,
        timeline: Vec::new(),
    }
}

fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn scan_sqlite_schema_tables(bytes: &[u8]) -> (bool, Vec<String>, Vec<ForensicEntry>) {
    let wal_mode = bytes.len() >= 20 && (bytes[18] == 2 || bytes[19] == 2);
    let mut tables = BTreeSet::new();
    let mut entries = Vec::new();
    let lossy = String::from_utf8_lossy(bytes);
    let upper = lossy.to_ascii_uppercase();
    for stmt_prefix in ["CREATE TABLE ", "CREATE VIRTUAL TABLE ", "CREATE VIEW "] {
        let mut idx = 0usize;
        while let Some(found) = upper[idx..].find(stmt_prefix) {
            let start = idx + found;
            let trimmed_after = lossy[start + stmt_prefix.len()..].trim_start();
            let after = if trimmed_after
                .as_bytes()
                .get(..14)
                .is_some_and(|b| b.eq_ignore_ascii_case(b"IF NOT EXISTS "))
            {
                trimmed_after[14..].trim_start()
            } else {
                trimmed_after
            };
            let name_end = after
                .find(|c: char| c.is_whitespace() || c == '(')
                .unwrap_or_else(|| floor_char_boundary(after, after.len().min(80)));
            let raw_tbl = after[..name_end].trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']');
            let tbl = raw_tbl
                .strip_prefix("main.")
                .or_else(|| raw_tbl.strip_prefix("MAIN."))
                .unwrap_or(raw_tbl)
                .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']');
            if !tbl.is_empty() && tbl.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                tables.insert(tbl.to_string());
                let fallback_end = floor_char_boundary(&lossy, (start + 120).min(lossy.len()));
                let stmt_end = lossy[start..]
                    .find(')')
                    .map(|p| floor_char_boundary(&lossy, (start + p + 1).min(start + 220).min(lossy.len())))
                    .unwrap_or(fallback_end);
                let snippet = lossy[start..stmt_end].replace(['\r', '\n'], " ");
                entries.push(ForensicEntry {
                    category: "SQLite Schema".to_string(),
                    name: tbl.to_string(),
                    detail: snippet,
                    size_bytes: None,
                });
            }
            let after_start = lossy.len() - after.len();
            idx = ceil_char_boundary(&lossy, (after_start + name_end.max(1)).min(lossy.len()));
        }
    }
    (wal_mode, tables.into_iter().collect(), entries)
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    if bytes.len() >= 8 && bytes.starts_with(&[0x03, 0x00, 0x08, 0x00]) {
        return true;
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]);
    let t = head.trim_start();
    t.starts_with("<?xml") || t.starts_with("<map") || t.starts_with("<manifest")
}

fn inspect_xml_bytes(
    path: &Path,
    bytes: &[u8],
    sha256: String,
    sha512: String,
    opts: &ForensicOptions,
) -> ForensicReport {
    let text = String::from_utf8_lossy(bytes);
    let mut entries = Vec::new();
    let mut permissions = BTreeSet::new();
    let mut warnings = Vec::new();
    let mut timeline = Vec::new();

    if opts.extract_manifest_permissions {
        permissions = scan_android_permissions(bytes);
    }

    let mut metadata = vec![("XML Lines".to_string(), text.lines().count().to_string())];

    if (bytes.len() >= 8 && bytes.starts_with(&[0x03, 0x00, 0x08, 0x00])) || text.contains("<manifest") {
        let sec = axml::parse_manifest_security(bytes);
        axml::append_manifest_security(&sec, &mut metadata, &mut warnings);
        if opts.extract_manifest_permissions {
            permissions.extend(sec.permissions);
        }
    }

    for tag in ["<string ", "<boolean ", "<int ", "<long ", "<float "] {
        let mut idx = 0usize;
        while entries.len() < opts.max_entries {
            let Some(pos) = text[idx..].find(tag) else {
                break;
            };
            let start = idx + pos;
            let rest = &text[start..];
            let end_rel = rest.find('>').unwrap_or(rest.len());
            let open_tag = &rest[..=end_rel.min(rest.len().saturating_sub(1))];
            let name = extract_xml_attr(open_tag, "name").unwrap_or_else(|| "<unnamed>".to_string());
            let val = extract_xml_attr(open_tag, "value").unwrap_or_else(|| {
                let after = &rest[end_rel.saturating_add(1).min(rest.len())..];
                after.split('<').next().unwrap_or("").trim().to_string()
            });
            if tag == "<long "
                && timeline.len() < opts.max_entries
                && let Ok(ms) = val.trim().parse::<i64>()
                && let Some(ts) = epoch_ms_to_rfc3339(ms)
            {
                timeline.push(TimelineEvent {
                    timestamp: ts,
                    source: "SharedPrefs".to_string(),
                    category: "Preference Epoch".to_string(),
                    target: name.clone(),
                    detail: val.clone(),
                });
            }
            entries.push(ForensicEntry {
                category: "SharedPrefs".to_string(),
                name,
                detail: val,
                size_bytes: None,
            });
            idx = start + tag.len();
        }
    }

    metadata.push(("Keys Extracted".to_string(), entries.len().to_string()));
    metadata.push(("Permissions Found".to_string(), permissions.len().to_string()));

    ForensicReport {
        path: path.display().to_string(),
        kind: ArtifactKind::XmlManifestOrPrefs,
        total_bytes: bytes.len() as u64,
        sha256,
        sha512,
        metadata,
        permissions_or_tables: permissions.into_iter().collect(),
        entries,
        warnings,
        timeline,
    }
}

pub(super) fn extract_xml_attr(line: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let mut offset = 0usize;
    while let Some(rel) = line[offset..].find(&needle) {
        let pos = offset + rel;
        let prev = pos.checked_sub(1).and_then(|i| line.as_bytes().get(i).copied());
        let boundary_ok = prev.is_none_or(|b| b.is_ascii_whitespace() || b == b':');
        let start = pos + needle.len();
        if boundary_ok {
            let end = line[start..].find('"')? + start;
            return Some(line[start..end].to_string());
        }
        offset = start.min(line.len());
    }
    None
}

fn parse_logcat_timestamp(line: &str) -> Option<String> {
    let b = line.as_bytes();
    if b.len() >= 21
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[10] == b' '
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[13] == b':'
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[16] == b':'
        && b[17..19].iter().all(u8::is_ascii_digit)
        && b[19] == b'.'
        && b[20].is_ascii_digit()
    {
        let mut end = 20;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if end < b.len() && b[end] == b'Z' {
            end += 1;
        } else if end + 6 <= b.len()
            && matches!(b[end], b'+' | b'-')
            && b[end + 1..end + 3].iter().all(u8::is_ascii_digit)
            && b[end + 3] == b':'
            && b[end + 4..end + 6].iter().all(u8::is_ascii_digit)
        {
            end += 6;
        }
        return Some(line[..end].replacen(' ', "T", 1));
    }
    if b.len() >= 18
        && b[0..2].iter().all(u8::is_ascii_digit)
        && b[2] == b'-'
        && b[3..5].iter().all(u8::is_ascii_digit)
        && b[5] == b' '
        && b[6..8].iter().all(u8::is_ascii_digit)
        && b[8] == b':'
        && b[9..11].iter().all(u8::is_ascii_digit)
        && b[11] == b':'
        && b[12..14].iter().all(u8::is_ascii_digit)
        && b[14] == b'.'
        && b[15..18].iter().all(u8::is_ascii_digit)
    {
        let mut end = 18;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        return Some(line[..end].to_string());
    }
    None
}

fn inspect_text_dump_bytes(
    path: &Path,
    bytes: &[u8],
    sha256: String,
    sha512: String,
    opts: &ForensicOptions,
) -> ForensicReport {
    let text = String::from_utf8_lossy(bytes);
    let mut entries = Vec::new();
    let mut timeline = Vec::new();
    let mut prop_count = 0usize;
    let mut err_count = 0usize;

    for (line_idx, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if timeline.len() < opts.max_entries
            && let Some(ts) = parse_logcat_timestamp(t)
        {
            let cat = if t.contains(" F ") || t.contains("FATAL EXCEPTION") {
                "Logcat Fatal"
            } else if t.contains(" E ") {
                "Logcat Error"
            } else {
                "Logcat Entry"
            };
            timeline.push(TimelineEvent {
                timestamp: ts,
                source: "Logcat".to_string(),
                category: cat.to_string(),
                target: format!("Line {}", line_idx + 1),
                detail: t.to_string(),
            });
        }
        if t.starts_with('[')
            && let Some((k, v)) = t.split_once("]: [")
        {
            prop_count += 1;
            if entries.len() < opts.max_entries {
                entries.push(ForensicEntry {
                    category: "Property".to_string(),
                    name: k.trim_start_matches('[').to_string(),
                    detail: v.trim_end_matches(']').to_string(),
                    size_bytes: None,
                });
            }
        } else if t.contains(" E ") || t.contains(" F ") || t.contains("FATAL EXCEPTION") || t.starts_with("E/") {
            err_count += 1;
            if entries.len() < opts.max_entries {
                entries.push(ForensicEntry {
                    category: "Logcat Error".to_string(),
                    name: format!("Line {}", line_idx + 1),
                    detail: t.to_string(),
                    size_bytes: None,
                });
            }
        }
    }

    ForensicReport {
        path: path.display().to_string(),
        kind: ArtifactKind::LogOrPropertyDump,
        total_bytes: bytes.len() as u64,
        sha256,
        sha512,
        metadata: vec![
            ("Total Lines".to_string(), text.lines().count().to_string()),
            ("System Properties".to_string(), prop_count.to_string()),
            ("Error / Fatal Lines".to_string(), err_count.to_string()),
        ],
        permissions_or_tables: Vec::new(),
        entries,
        warnings: Vec::new(),
        timeline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn inspects_unencrypted_ab_backup_and_sqlite_header() {
        let tmp = TempDir::new().unwrap();

        // Build synthetic SQLite 3 file with CREATE TABLE schema
        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        db[16..18].copy_from_slice(&4096u16.to_be_bytes());
        db[18] = 2; // WAL
        db[19] = 2;
        db[56..60].copy_from_slice(&1u32.to_be_bytes());
        let schema = b"CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, body TEXT)";
        db[120..120 + schema.len()].copy_from_slice(schema);

        // Build synthetic 512-byte TAR header + 4096-byte SQLite payload + 1024-byte trailer
        let mut tar = vec![0u8; 512 + db.len() + 1024];
        let name = b"apps/com.example.chat/db/msgstore.db";
        tar[..name.len()].copy_from_slice(name);
        let size_octal = format!("{:011o}\0", db.len());
        tar[124..124 + size_octal.len()].copy_from_slice(size_octal.as_bytes());
        tar[156] = b'0';
        tar[512..512 + db.len()].copy_from_slice(&db);

        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar).unwrap();
        let compressed_tar = enc.finish().unwrap();

        let mut ab_bytes = b"ANDROID BACKUP\n5\n1\nnone\n".to_vec();
        ab_bytes.extend_from_slice(&compressed_tar);
        let ab_path = tmp.path().join("evidence.ab");
        std::fs::write(&ab_path, &ab_bytes).unwrap();

        let ab_report = inspect_artifact(&ab_path, &ForensicOptions::default()).unwrap();
        assert_eq!(ab_report.kind, ArtifactKind::AndroidBackupAb);
        assert!(
            ab_report
                .entries
                .iter()
                .any(|e| e.name.contains("msgstore.db") && e.detail.contains("SQLite 3"))
        );
        assert!(ab_report.permissions_or_tables.contains(&"messages".to_string()));

        let db_path = tmp.path().join("msgstore.db");
        std::fs::write(&db_path, &db).unwrap();

        let db_report = inspect_artifact(&db_path, &ForensicOptions::default()).unwrap();
        assert_eq!(db_report.kind, ArtifactKind::SqliteDatabase);
        assert!(db_report.permissions_or_tables.contains(&"messages".to_string()));
        assert!(!db_report.warnings.is_empty());
    }

    #[test]
    fn inspects_minimal_apk_zip_manifest_permissions() {
        let tmp = TempDir::new().unwrap();
        let manifest_payload = b"<manifest package=\"com.demo\"><uses-permission android:name=\"android.permission.READ_CONTACTS\"/></manifest>";
        let name = b"AndroidManifest.xml";
        let mut zip = Vec::new();
        // Local File Header
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // stored
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(manifest_payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(manifest_payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name);
        zip.extend_from_slice(manifest_payload);

        let apk_path = tmp.path().join("sample.apk");
        std::fs::write(&apk_path, &zip).unwrap();

        let rep = inspect_artifact(&apk_path, &ForensicOptions::default()).unwrap();
        assert_eq!(rep.kind, ArtifactKind::ApkPackage);
        assert!(
            rep.permissions_or_tables
                .contains(&"android.permission.READ_CONTACTS".to_string())
        );
    }

    fn push_zip_entry_and_cd(zip: &mut Vec<u8>, cd: &mut Vec<u8>, local_name: &[u8], cd_name: &[u8], payload: &[u8]) {
        let local_offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(local_name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(local_name);
        zip.extend_from_slice(payload);

        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(cd_name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&local_offset.to_le_bytes());
        cd.extend_from_slice(cd_name);
    }

    fn finish_zip_with_cd(zip: &mut Vec<u8>, cd: &[u8], entries: u16) {
        let cd_offset = zip.len() as u32;
        zip.extend_from_slice(cd);
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&entries.to_le_bytes());
        zip.extend_from_slice(&entries.to_le_bytes());
        zip.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        zip.extend_from_slice(&cd_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
    }

    #[test]
    fn detects_zip_slip_bidi_and_local_central_mismatch() {
        assert!(detect_suspicious_entry_name("a\0b").is_some());
        assert!(detect_suspicious_entry_name(r"C:\Windows\bad.dll").is_some());

        let tmp = TempDir::new().unwrap();
        let mut zip = Vec::new();
        let mut cd = Vec::new();
        push_zip_entry_and_cd(&mut zip, &mut cd, b"safe.txt", b"../evil.txt", b"hi");
        let bidi_name = "invoice_\u{202E}gpj.exe";
        push_zip_entry_and_cd(&mut zip, &mut cd, bidi_name.as_bytes(), bidi_name.as_bytes(), b"hi");
        finish_zip_with_cd(&mut zip, &cd, 2);

        let apk_path = tmp.path().join("tampered.zip");
        std::fs::write(&apk_path, &zip).unwrap();

        let rep = inspect_artifact(&apk_path, &ForensicOptions::default()).unwrap();
        let joined = rep.warnings.join("\n");
        assert!(joined.contains("traversal"), "expected Zip-Slip warning in: {joined}");
        assert!(joined.contains("BiDi"), "expected BiDi warning in: {joined}");
        assert!(
            joined.contains("Local-vs-Central filename mismatch"),
            "expected Local-vs-Central mismatch warning in: {joined}"
        );
    }

    #[test]
    fn detects_apk_sig_block_v2_without_false_unsigned_warning() {
        let tmp = TempDir::new().unwrap();
        let mut zip = Vec::new();
        let mut cd = Vec::new();
        let manifest_payload = b"<manifest package=\"com.v2demo\"><uses-permission android:name=\"android.permission.CAMERA\"/></manifest>";
        push_zip_entry_and_cd(
            &mut zip,
            &mut cd,
            b"AndroidManifest.xml",
            b"AndroidManifest.xml",
            manifest_payload,
        );

        // Append valid APK Signing Block immediately before Central Directory
        let pair_value = b"sig2";
        let pair_len: u64 = 4 + pair_value.len() as u64;
        let block_body_len: u64 = (8 + pair_len) + 8 + 16;
        zip.extend_from_slice(&block_body_len.to_le_bytes());
        zip.extend_from_slice(&pair_len.to_le_bytes());
        zip.extend_from_slice(&0x7109_871au32.to_le_bytes());
        zip.extend_from_slice(pair_value);
        zip.extend_from_slice(&block_body_len.to_le_bytes());
        zip.extend_from_slice(b"APK Sig Block 42");

        finish_zip_with_cd(&mut zip, &cd, 1);

        let apk_path = tmp.path().join("signed_v2.apk");
        std::fs::write(&apk_path, &zip).unwrap();

        let rep = inspect_artifact(&apk_path, &ForensicOptions::default()).unwrap();
        let sig_meta = rep
            .metadata
            .iter()
            .find(|(k, _)| k == "Signature Schemes")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        assert!(
            sig_meta.contains("v2"),
            "expected v2 scheme in metadata, got {sig_meta:?}"
        );
        assert!(
            !rep.warnings.iter().any(|w| w.contains("unsigned")),
            "unexpected unsigned warning: {:?}",
            rep.warnings
        );
    }

    #[test]
    fn inspects_sqlite_freelist_and_companion_wal_stream() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("messages.db");
        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        db[16..18].copy_from_slice(&4096u16.to_be_bytes());
        db[18] = 2; // WAL write version
        db[19] = 2; // WAL read version
        db[28..32].copy_from_slice(&1u32.to_be_bytes());
        db[36..40].copy_from_slice(&3u32.to_be_bytes()); // freelist pages
        db[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
        db[60..64].copy_from_slice(&42u32.to_be_bytes()); // user_version
        db[68..72].copy_from_slice(&0x4142_4344u32.to_be_bytes()); // application_id
        std::fs::write(&db_path, &db).unwrap();

        let wal_path = tmp.path().join("messages.db-wal");
        let mut wal = vec![0u8; 32 + 24 + 4096];
        wal[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        wal[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        wal[8..12].copy_from_slice(&4096u32.to_be_bytes());
        std::fs::write(&wal_path, &wal).unwrap();

        let rep = inspect_artifact(&db_path, &ForensicOptions::default()).unwrap();
        assert_eq!(rep.kind, ArtifactKind::SqliteDatabase);
        assert!(rep.metadata.contains(&("Freelist Pages".to_string(), "3".to_string())));
        assert!(rep.metadata.contains(&("User Version".to_string(), "42".to_string())));
        assert!(
            rep.metadata
                .contains(&("Application ID".to_string(), "0x41424344".to_string()))
        );
        assert!(rep.entries.iter().any(|e| {
            e.category == "SQLite Companion"
                && e.name == "messages.db-wal"
                && e.detail.contains("1 frame(s)")
                && e.detail.contains("sha256=")
        }));
        let joined = rep.warnings.join("\n");
        assert!(joined.contains("freelist"), "expected freelist warning in: {joined}");
        assert!(
            joined.contains("companion -wal detected"),
            "expected WAL companion note in: {joined}"
        );
    }

    #[test]
    fn read_bounded_truncates_large_deflate_payload() {
        let mut compressed = Vec::new();
        {
            let mut enc = flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::fast());
            std::io::Write::write_all(&mut enc, &vec![b'A'; 128 * 1024]).unwrap();
            enc.finish().unwrap();
        }

        let (capped, truncated) = read_bounded(ZlibDecoder::new(compressed.as_slice()), 4096).unwrap();
        assert!(truncated);
        assert_eq!(capped.len(), 4096);

        let (full, full_trunc) = read_bounded(ZlibDecoder::new(compressed.as_slice()), 256 * 1024).unwrap();
        assert!(!full_trunc);
        assert_eq!(full.len(), 128 * 1024);
    }

    fn push_abx_new_interned(buf: &mut Vec<u8>, s: &str) {
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes());
        buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
    }

    #[test]
    fn parses_abx_binary_xml_and_extracts_timeline() {
        let tmp = TempDir::new().unwrap();
        let mut abx = b"ABX\0".to_vec();
        abx.push(0x00); // START_DOCUMENT
        abx.push(0x32); // START_TAG
        push_abx_new_interned(&mut abx, "packages");
        abx.push(0x32); // START_TAG
        push_abx_new_interned(&mut abx, "package");
        abx.push(0x3F); // ATTRIBUTE | TYPE_STRING_INTERNED
        push_abx_new_interned(&mut abx, "name");
        push_abx_new_interned(&mut abx, "com.example.chat");
        abx.push(0x8F); // ATTRIBUTE | TYPE_LONG
        push_abx_new_interned(&mut abx, "itTimestamp");
        abx.extend_from_slice(&1_700_000_000_000i64.to_be_bytes());
        abx.push(0xCF); // ATTRIBUTE | TYPE_BOOLEAN_TRUE
        push_abx_new_interned(&mut abx, "system");
        abx.push(0x33); // END_TAG "package" (interned idx 1)
        abx.extend_from_slice(&1u16.to_be_bytes());
        abx.push(0x33); // END_TAG "packages" (interned idx 0)
        abx.extend_from_slice(&0u16.to_be_bytes());
        abx.push(0x01); // END_DOCUMENT

        let path = tmp.path().join("packages.abx");
        std::fs::write(&path, &abx).unwrap();

        let rep = inspect_artifact(&path, &ForensicOptions::default()).unwrap();
        assert_eq!(rep.kind, ArtifactKind::AndroidBinaryXml);
        assert!(rep.entries.iter().any(|e| {
            e.category == "ABX Attribute" && e.name == "packages/package@name" && e.detail == "com.example.chat"
        }));
        assert!(
            rep.entries
                .iter()
                .any(|e| e.name == "packages/package@system" && e.detail == "true")
        );
        assert!(
            rep.timeline
                .iter()
                .any(|t| t.source == "ABX" && t.target == "packages/package@itTimestamp"),
            "expected ABX epoch timestamp in timeline: {:?}",
            rep.timeline
        );
    }

    type TestAxmlAttr = (i32, i32, u8, u32);
    type TestAxmlElement = (u32, Vec<TestAxmlAttr>);

    fn build_test_axml_bytes(strings: &[&str], res_ids: &[u32], elements: &[TestAxmlElement]) -> Vec<u8> {
        // Build UTF-8 RES_STRING_POOL_TYPE chunk
        let mut pool_data = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(pool_data.len() as u32);
            let char_len = s.chars().count() as u8;
            let byte_len = s.len() as u8;
            pool_data.push(char_len);
            pool_data.push(byte_len);
            pool_data.extend_from_slice(s.as_bytes());
            pool_data.push(0);
        }
        while !pool_data.len().is_multiple_of(4) {
            pool_data.push(0);
        }

        let header_size = 28u16;
        let strings_start = u32::from(header_size) + (strings.len() as u32) * 4;
        let pool_size = strings_start + pool_data.len() as u32;
        let mut chunks = Vec::new();

        // StringPool chunk
        chunks.extend_from_slice(&0x0001u16.to_le_bytes());
        chunks.extend_from_slice(&header_size.to_le_bytes());
        chunks.extend_from_slice(&pool_size.to_le_bytes());
        chunks.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        chunks.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        chunks.extend_from_slice(&0x0100u32.to_le_bytes()); // UTF8_FLAG
        chunks.extend_from_slice(&strings_start.to_le_bytes());
        chunks.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        for off in offsets {
            chunks.extend_from_slice(&off.to_le_bytes());
        }
        chunks.extend_from_slice(&pool_data);

        // ResourceMap chunk
        let rmap_size = 8 + (res_ids.len() as u32) * 4;
        chunks.extend_from_slice(&0x0180u16.to_le_bytes());
        chunks.extend_from_slice(&8u16.to_le_bytes());
        chunks.extend_from_slice(&rmap_size.to_le_bytes());
        for id in res_ids {
            chunks.extend_from_slice(&id.to_le_bytes());
        }

        // StartElement chunks
        for (elem_idx, attrs) in elements {
            let elem_size = 16 + 20 + (attrs.len() as u32) * 20;
            chunks.extend_from_slice(&0x0102u16.to_le_bytes());
            chunks.extend_from_slice(&16u16.to_le_bytes());
            chunks.extend_from_slice(&elem_size.to_le_bytes());
            chunks.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
            chunks.extend_from_slice(&(-1i32).to_le_bytes()); // comment
            chunks.extend_from_slice(&(-1i32).to_le_bytes()); // ns
            chunks.extend_from_slice(&elem_idx.to_le_bytes());
            chunks.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
            chunks.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
            chunks.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
            chunks.extend_from_slice(&0u16.to_le_bytes());
            chunks.extend_from_slice(&0u16.to_le_bytes());
            chunks.extend_from_slice(&0u16.to_le_bytes());
            for (name_idx, raw_val_idx, data_type, data) in attrs {
                chunks.extend_from_slice(&(-1i32).to_le_bytes());
                chunks.extend_from_slice(&name_idx.to_le_bytes());
                chunks.extend_from_slice(&raw_val_idx.to_le_bytes());
                chunks.extend_from_slice(&8u16.to_le_bytes());
                chunks.push(0);
                chunks.push(*data_type);
                chunks.extend_from_slice(&data.to_le_bytes());
            }
        }

        let mut axml = Vec::new();
        axml.extend_from_slice(&[0x03, 0x00, 0x08, 0x00]);
        axml.extend_from_slice(&(8 + chunks.len() as u32).to_le_bytes());
        axml.extend_from_slice(&chunks);
        axml
    }

    #[test]
    fn parses_binary_axml_manifest_security_and_warnings() {
        let tmp = TempDir::new().unwrap();
        let strings = [
            "name",
            "debuggable",
            "minSdkVersion",
            "versionCode",
            "versionName",
            "targetSdkVersion",
            "allowBackup",
            "package",
            "manifest",
            "uses-sdk",
            "application",
            "uses-permission",
            "com.example.bank",
            "2.4.1",
            "android.permission.RECORD_AUDIO",
        ];
        let res_ids = [
            0x0101_0003,
            0x0101_000f,
            0x0101_020c,
            0x0101_021b,
            0x0101_021c,
            0x0101_0270,
            0x0101_0280,
        ];
        let axml = build_test_axml_bytes(
            &strings,
            &res_ids,
            &[
                (8, vec![(7, 12, 0x03, 12), (3, -1, 0x10, 42), (4, 13, 0x03, 13)]),
                (9, vec![(2, -1, 0x10, 26), (5, -1, 0x10, 35)]),
                (10, vec![(1, -1, 0x12, 1), (6, -1, 0x12, 1)]),
                (11, vec![(0, 14, 0x03, 14)]),
            ],
        );

        let mut zip = Vec::new();
        let mut cd = Vec::new();
        push_zip_entry_and_cd(&mut zip, &mut cd, b"AndroidManifest.xml", b"AndroidManifest.xml", &axml);
        // Patch non-zero DOS time/date into CD entry to exercise ZIP timeline extraction
        // 2025-06-15 -> ((2025-1980)<<9)|(6<<5)|15 = 0x5ACF, 12:30:00 -> (12<<11)|(30<<5)|0 = 0x63C0
        cd[12..14].copy_from_slice(&0x63C0u16.to_le_bytes());
        cd[14..16].copy_from_slice(&0x5ACFu16.to_le_bytes());
        finish_zip_with_cd(&mut zip, &cd, 1);

        let apk_path = tmp.path().join("axml_app.apk");
        std::fs::write(&apk_path, &zip).unwrap();

        let rep = inspect_artifact(&apk_path, &ForensicOptions::default()).unwrap();
        assert_eq!(rep.kind, ArtifactKind::ApkPackage);
        assert!(
            rep.metadata
                .contains(&("Package Name".to_string(), "com.example.bank".to_string()))
        );
        assert!(
            rep.metadata
                .contains(&("Version Name".to_string(), "2.4.1".to_string()))
        );
        assert!(rep.metadata.contains(&("Version Code".to_string(), "42".to_string())));
        assert!(rep.metadata.contains(&("Min SDK".to_string(), "26".to_string())));
        assert!(rep.metadata.contains(&("Target SDK".to_string(), "35".to_string())));
        assert!(rep.metadata.contains(&("Debuggable".to_string(), "true".to_string())));
        assert!(rep.metadata.contains(&("Allow Backup".to_string(), "true".to_string())));
        assert!(
            rep.permissions_or_tables
                .contains(&"android.permission.RECORD_AUDIO".to_string())
        );
        let joined = rep.warnings.join("\n");
        assert!(
            joined.contains("debuggable=\"true\""),
            "expected debuggable warning: {joined}"
        );
        assert!(
            joined.contains("allowBackup=\"true\""),
            "expected allowBackup warning: {joined}"
        );
        assert!(
            rep.timeline
                .iter()
                .any(|t| t.source == "APK/ZIP DOS" && t.target == "AndroidManifest.xml"),
            "expected DOS timestamp timeline event"
        );
    }

    #[test]
    fn inspects_adb_bugreport_zip_tombstones_and_usagestats_timeline() {
        let tmp = TempDir::new().unwrap();
        let mut zip = Vec::new();
        let mut cd = Vec::new();
        let main_txt = "\
== dumpstate: 2025-02-01 10:15:30
Build: AP2A.240905.003
Build fingerprint: 'google/panther/panther:15/AP2A'
DUMP OF SERVICE package:
  Package [com.demo.messenger] (12345):
DUMP OF SERVICE usagestats:
  time=\"2025-02-01 10:14:00\" type=MOVE_TO_FOREGROUND package=com.demo.messenger
DUMP OF SERVICE account:
  Account {name=alice@example.com, type=com.google}
DUMP OF SERVICE battery:
  level: 84
";
        push_zip_entry_and_cd(&mut zip, &mut cd, b"version.txt", b"version.txt", b"bugreport-v1");
        push_zip_entry_and_cd(
            &mut zip,
            &mut cd,
            b"main_entry.txt",
            b"main_entry.txt",
            b"bugreport-panther.txt",
        );
        push_zip_entry_and_cd(
            &mut zip,
            &mut cd,
            b"bugreport-panther.txt",
            b"bugreport-panther.txt",
            main_txt.as_bytes(),
        );
        push_zip_entry_and_cd(
            &mut zip,
            &mut cd,
            b"FS/data/tombstones/tombstone_00",
            b"FS/data/tombstones/tombstone_00",
            b"Build fingerprint: crash",
        );
        finish_zip_with_cd(&mut zip, &cd, 4);

        let zip_path = tmp.path().join("bugreport.zip");
        std::fs::write(&zip_path, &zip).unwrap();

        let rep = inspect_artifact(&zip_path, &ForensicOptions::default()).unwrap();
        assert_eq!(rep.kind, ArtifactKind::BugreportZip);
        assert!(
            rep.metadata
                .contains(&("Build ID".to_string(), "AP2A.240905.003".to_string()))
        );
        assert!(
            rep.metadata
                .contains(&("Native Tombstones".to_string(), "1".to_string()))
        );
        assert!(
            rep.metadata
                .contains(&("Packages Enumerated".to_string(), "1".to_string()))
        );
        assert!(
            rep.metadata
                .contains(&("Accounts Discovered".to_string(), "1".to_string()))
        );
        assert!(rep.metadata.contains(&("Battery Level".to_string(), "84%".to_string())));
        assert!(rep.permissions_or_tables.contains(&"com.demo.messenger".to_string()));
        assert!(rep.warnings.iter().any(|w| w.contains("tombstone")));
        assert!(rep.timeline.iter().any(|t| t.source == "UsageStats"
            && t.target == "com.demo.messenger"
            && t.timestamp == "2025-02-01T10:14:00"));
    }

    #[test]
    fn inspects_and_decrypts_password_protected_ab_backup() {
        let tmp = TempDir::new().unwrap();

        let xml_payload = b"<map><long name=\"last_sync\" value=\"1700000000000\"/></map>";
        let mut tar = vec![0u8; 512 + 512 + 1024];
        let tar_name = b"apps/com.secret/sp/prefs.xml";
        tar[..tar_name.len()].copy_from_slice(tar_name);
        let sz_oct = format!("{:011o}\0", xml_payload.len());
        tar[124..124 + sz_oct.len()].copy_from_slice(sz_oct.as_bytes());
        tar[136..148].copy_from_slice(b"14500000000\0");
        tar[156] = b'0';
        tar[512..512 + xml_payload.len()].copy_from_slice(xml_payload);

        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar).unwrap();
        let compressed_tar = enc.finish().unwrap();

        let runtime_seed = format!(
            "{}:{}:{}",
            tmp.path().display(),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        let mut pw_hasher = Sha256::new();
        pw_hasher.update(runtime_seed.as_bytes());
        let pw_digest = encode_hex_lower(&pw_hasher.finalize());
        let good_pass = pw_digest[..24].to_string();
        let wrong_pass: String = good_pass.bytes().map(|b| if b == b'0' { '1' } else { '0' }).collect();

        let ab_bytes = ab_crypto::encrypt_ab_v5_for_test(&compressed_tar, &good_pass, 100, runtime_seed.as_bytes());
        let ab_path = tmp.path().join("encrypted.ab");
        std::fs::write(&ab_path, &ab_bytes).unwrap();

        // 1. No password -> metadata exposes PBKDF2 rounds + warning
        let rep_locked = inspect_artifact(&ab_path, &ForensicOptions::default()).unwrap();
        assert!(
            rep_locked
                .metadata
                .contains(&("PBKDF2 Rounds".to_string(), "100".to_string()))
        );
        assert!(rep_locked.warnings.iter().any(|w| w.contains("--password")));

        // 2. Wrong password -> verification error warning
        let wrong_opts = ForensicOptions {
            ab_password: Some(wrong_pass),
            ..Default::default()
        };
        let rep_wrong = inspect_artifact(&ab_path, &wrong_opts).unwrap();
        assert!(rep_wrong.warnings.iter().any(|w| w.contains("password")));

        // 3. Correct password + serde skip verification
        let good_opts = ForensicOptions {
            ab_password: Some(good_pass.clone()),
            case_meta: crate::model::CaseMetadata {
                case_id: Some("CASE-42".to_string()),
                evidence_id: Some("EV-01".to_string()),
                examiner: Some("A. Examiner".to_string()),
            },
            ..Default::default()
        };
        let serialized_opts = serde_json::to_string(&good_opts).unwrap();
        assert!(!serialized_opts.contains(&good_pass));

        let rep_ok = inspect_artifact(&ab_path, &good_opts).unwrap();
        assert_eq!(rep_ok.sha256.len(), 64);
        assert_eq!(rep_ok.sha512.len(), 128);
        assert_eq!(rep_ok.metadata[0], ("Case ID".to_string(), "CASE-42".to_string()));
        assert!(
            rep_ok
                .metadata
                .contains(&("Decryption Status".to_string(), "Verified & Decrypted".to_string()))
        );
        assert!(rep_ok.entries.iter().any(|e| e.name == "apps/com.secret/sp/prefs.xml"));
        assert!(
            rep_ok
                .timeline
                .iter()
                .any(|t| t.source == "TAR mtime" && t.target == "apps/com.secret/sp/prefs.xml")
        );
    }

    #[test]
    fn abx_deep_nesting_stops_at_depth_cap() {
        let tmp = TempDir::new().unwrap();
        let mut abx = b"ABX\0".to_vec();
        abx.push(0x00); // START_DOCUMENT
        abx.push(0x32); // START_TAG
        push_abx_new_interned(&mut abx, "node");
        for _ in 0..140 {
            abx.push(0x32);
            abx.extend_from_slice(&0u16.to_be_bytes());
        }
        abx.push(0x01); // END_DOCUMENT

        let path = tmp.path().join("deep.abx");
        std::fs::write(&path, &abx).unwrap();

        let rep = inspect_artifact(&path, &ForensicOptions::default()).unwrap();
        assert_eq!(rep.kind, ArtifactKind::AndroidBinaryXml);
        assert!(
            rep.warnings.iter().any(|w| w.contains("nesting exceeded")),
            "expected nesting cap warning, got: {:?}",
            rep.warnings
        );
    }

    #[test]
    fn bugreport_utf8_timestamp_and_bootloader_radio_do_not_panic() {
        let tmp = TempDir::new().unwrap();
        let mut zip = Vec::new();
        let mut cd = Vec::new();
        let main_txt = "Bootloader: slider-1.2\nRadio: g5300q-2501\nDUMP OF SERVICE usagestats:\n  time=\"2025-02-01 \u{1F600}\u{1F600}\u{1F600}\" type=TEST package=com.utf8.test\n";
        push_zip_entry_and_cd(
            &mut zip,
            &mut cd,
            b"bugreport-utf8.txt",
            b"bugreport-utf8.txt",
            main_txt.as_bytes(),
        );
        finish_zip_with_cd(&mut zip, &cd, 1);

        let zip_path = tmp.path().join("bugreport_utf8.zip");
        std::fs::write(&zip_path, &zip).unwrap();

        let rep = inspect_artifact(&zip_path, &ForensicOptions::default()).unwrap();
        assert_eq!(rep.kind, ArtifactKind::BugreportZip);
        assert!(
            rep.metadata
                .contains(&("Bootloader".to_string(), "slider-1.2".to_string()))
        );
        assert!(rep.metadata.contains(&("Radio".to_string(), "g5300q-2501".to_string())));
    }

    #[test]
    fn extract_xml_attr_ignores_attribute_suffix_collisions() {
        assert_eq!(
            extract_xml_attr(r#"<string foo_name="wrong" name="right">"#, "name"),
            Some("right".to_string())
        );
        assert_eq!(
            extract_xml_attr(
                r#"<uses-permission custom_name="wrong" android:name="android.permission.CAMERA"/>"#,
                "name"
            ),
            Some("android.permission.CAMERA".to_string())
        );
    }

    #[test]
    fn malformed_sqlite_and_logcat_utf8_boundaries_do_not_panic() {
        let tmp = TempDir::new().unwrap();

        // Binary SQLite with non-UTF8 (0xFF -> U+FFFD) bytes inside CREATE TABLE payloads
        let mut sqlite = vec![0u8; 4096];
        sqlite[..16].copy_from_slice(b"SQLite format 3\0");
        sqlite[16..18].copy_from_slice(&4096u16.to_be_bytes());
        sqlite[56..60].copy_from_slice(&1u32.to_be_bytes());
        let p1 = b"CREATE TABLE ";
        sqlite[120..120 + p1.len()].copy_from_slice(p1);
        sqlite[120 + p1.len()..120 + p1.len() + 6].fill(0xFF);
        let p2 = b"CREATE TABLE long_tbl(";
        sqlite[200..200 + p2.len()].copy_from_slice(p2);
        sqlite[200 + p2.len()..460].fill(0xFE);
        let db_path = tmp.path().join("fuzzed.db");
        std::fs::write(&db_path, &sqlite).unwrap();
        let db_rep = inspect_artifact(&db_path, &ForensicOptions::default()).unwrap();
        assert_eq!(db_rep.kind, ArtifactKind::SqliteDatabase);

        // Logcat timestamp with multibyte UTF-8 immediately after dot must not panic
        assert_eq!(parse_logcat_timestamp("01-02 03:04:05.\u{00E9}\u{00E9}"), None);
        assert_eq!(
            parse_logcat_timestamp("2025-05-01 09:00:00.123456  1000  1001 E Tag: msg"),
            Some("2025-05-01T09:00:00.123456".to_string())
        );

        // Error line number reflects actual file line index (line 3)
        let log_path = tmp.path().join("lines.log");
        std::fs::write(
            &log_path,
            "info one\ninfo two\n11-19 12:00:01.123  1000  1001 E Tag: boom\n",
        )
        .unwrap();
        let log_rep = inspect_artifact(&log_path, &ForensicOptions::default()).unwrap();
        assert!(log_rep.entries.iter().any(|e| e.name == "Line 3"));
    }

    #[test]
    fn manifest_detects_test_only_network_config_exported_and_caps_abx_timeline() {
        let tmp = TempDir::new().unwrap();
        let manifest = br#"<manifest package="com.sec.test">
            <application android:testOnly="true" android:networkSecurityConfig="@xml/nsc">
                <activity android:name=".Main" android:exported="true"/>
                <service android:name=".Svc" android:exported="true"/>
            </application>
        </manifest>"#;
        let xml_path = tmp.path().join("AndroidManifest.xml");
        std::fs::write(&xml_path, manifest).unwrap();
        let rep = inspect_artifact(&xml_path, &ForensicOptions::default()).unwrap();
        assert!(rep.metadata.contains(&("Test Only".to_string(), "true".to_string())));
        assert!(
            rep.metadata
                .contains(&("Network Security Config".to_string(), "Configured".to_string()))
        );
        assert!(
            rep.metadata
                .contains(&("Exported Components".to_string(), "2".to_string()))
        );
        assert!(rep.warnings.iter().any(|w| w.contains("testOnly=\"true\"")));

        // ABX timeline is bounded by max_entries
        let mut abx = b"ABX\0".to_vec();
        abx.push(0x00);
        abx.push(0x32);
        push_abx_new_interned(&mut abx, "root");
        for i in 0..20 {
            abx.push(0x8F);
            push_abx_new_interned(&mut abx, &format!("ts{i}"));
            abx.extend_from_slice(&(1_700_000_000_000i64 + i).to_be_bytes());
        }
        abx.push(0x33);
        abx.extend_from_slice(&0u16.to_be_bytes());
        abx.push(0x01);
        let abx_path = tmp.path().join("many_ts.abx");
        std::fs::write(&abx_path, &abx).unwrap();
        let opts = ForensicOptions {
            max_entries: 5,
            ..Default::default()
        };
        let abx_rep = inspect_artifact(&abx_path, &opts).unwrap();
        assert_eq!(abx_rep.timeline.len(), 5);
    }
}
