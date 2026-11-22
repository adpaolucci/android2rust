use super::{
    ArtifactKind, ForensicEntry, ForensicReport, TimelineEvent, ZipEntryMeta, dos_datetime_to_rfc3339,
    extract_zip_entry_bytes_with_cap,
};
use crate::format::format_bytes;
use crate::model::ForensicOptions;
use std::collections::BTreeSet;
use std::path::Path;

pub(super) const MAX_BUGREPORT_TEXT_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn is_bugreport_zip(zip_entries: &[ZipEntryMeta], has_manifest: bool) -> bool {
    if has_manifest {
        return false;
    }
    let mut has_main_entry = false;
    let mut has_version = false;
    for ze in zip_entries {
        let lower = ze.name.to_ascii_lowercase();
        if !lower.contains('/') && lower.starts_with("bugreport-") && lower.ends_with(".txt") {
            return true;
        }
        if lower == "main_entry.txt" {
            has_main_entry = true;
        } else if lower == "version.txt" {
            has_version = true;
        } else if lower.starts_with("fs/data/tombstones/") || lower.starts_with("fs/data/anr/") {
            return true;
        }
    }
    has_main_entry && has_version
}

pub(super) fn inspect_bugreport_zip_bytes(
    path: &Path,
    bytes: &[u8],
    sha256: String,
    sha512: String,
    zip_entries: &[ZipEntryMeta],
    mut warnings: Vec<String>,
    opts: &ForensicOptions,
) -> ForensicReport {
    let mut metadata = Vec::new();
    let mut entries = Vec::new();
    let mut timeline = Vec::new();
    let mut permissions_or_tables = Vec::new();

    metadata.push(("ZIP Entries".to_string(), zip_entries.len().to_string()));

    // Read version.txt if present
    if let Some(ver_ze) = zip_entries.iter().find(|z| z.name.eq_ignore_ascii_case("version.txt"))
        && let Some((ver_bytes, _)) = extract_zip_entry_bytes_with_cap(bytes, ver_ze, 4096)
    {
        let ver = String::from_utf8_lossy(&ver_bytes).trim().to_string();
        if !ver.is_empty() {
            metadata.push(("Bugreport Format Version".to_string(), ver));
        }
    }

    // Locate main bugreport text via main_entry.txt or bugreport-*.txt
    let main_entry_name = zip_entries
        .iter()
        .find(|z| z.name.eq_ignore_ascii_case("main_entry.txt"))
        .and_then(|ze| extract_zip_entry_bytes_with_cap(bytes, ze, 4096))
        .map(|(b, _)| String::from_utf8_lossy(&b).trim().to_string())
        .filter(|s| !s.is_empty());

    let main_ze = main_entry_name
        .as_deref()
        .and_then(|name| zip_entries.iter().find(|z| z.name == name))
        .or_else(|| {
            zip_entries.iter().find(|z| {
                let l = z.name.to_ascii_lowercase();
                !l.contains('/') && l.starts_with("bugreport-") && l.ends_with(".txt")
            })
        });

    let mut tombstones = 0usize;
    let mut anr_traces = 0usize;
    for ze in zip_entries {
        let lower = ze.name.to_ascii_lowercase();
        let tail = ze.name.rsplit('/').next().unwrap_or("");
        if lower.starts_with("fs/data/tombstones/") && !tail.is_empty() {
            tombstones += 1;
            if entries.len() < opts.max_entries {
                entries.push(ForensicEntry {
                    category: "Tombstone".to_string(),
                    name: ze.name.clone(),
                    detail: format_bytes(u64::from(ze.uncompressed_size)),
                    size_bytes: Some(u64::from(ze.uncompressed_size)),
                });
            }
            if timeline.len() < opts.max_entries
                && let Some(ts) = dos_datetime_to_rfc3339(ze.mod_date, ze.mod_time)
            {
                timeline.push(TimelineEvent {
                    timestamp: ts,
                    source: "Bugreport Tombstone".to_string(),
                    category: "Crash Artifact".to_string(),
                    target: ze.name.clone(),
                    detail: format_bytes(u64::from(ze.uncompressed_size)),
                });
            }
        } else if lower.starts_with("fs/data/anr/") && !tail.is_empty() {
            anr_traces += 1;
            if entries.len() < opts.max_entries {
                entries.push(ForensicEntry {
                    category: "ANR Trace".to_string(),
                    name: ze.name.clone(),
                    detail: format_bytes(u64::from(ze.uncompressed_size)),
                    size_bytes: Some(u64::from(ze.uncompressed_size)),
                });
            }
            if timeline.len() < opts.max_entries
                && let Some(ts) = dos_datetime_to_rfc3339(ze.mod_date, ze.mod_time)
            {
                timeline.push(TimelineEvent {
                    timestamp: ts,
                    source: "Bugreport ANR".to_string(),
                    category: "ANR Artifact".to_string(),
                    target: ze.name.clone(),
                    detail: format_bytes(u64::from(ze.uncompressed_size)),
                });
            }
        } else if timeline.len() < opts.max_entries
            && (lower == "main_entry.txt" || (!lower.contains('/') && lower.starts_with("bugreport-")))
            && let Some(ts) = dos_datetime_to_rfc3339(ze.mod_date, ze.mod_time)
        {
            timeline.push(TimelineEvent {
                timestamp: ts,
                source: "Bugreport ZIP".to_string(),
                category: "Archive Entry Modified".to_string(),
                target: ze.name.clone(),
                detail: format_bytes(u64::from(ze.uncompressed_size)),
            });
        }
    }

    if let Some(ze) = main_ze {
        metadata.push(("Main Bugreport Entry".to_string(), ze.name.clone()));
        if let Some((text_bytes, truncated)) = extract_zip_entry_bytes_with_cap(bytes, ze, MAX_BUGREPORT_TEXT_BYTES) {
            if truncated {
                warnings.push(format!(
                    "Main bugreport '{}' exceeded {} MiB inspection cap; parsed leading prefix.",
                    ze.name,
                    MAX_BUGREPORT_TEXT_BYTES / (1024 * 1024)
                ));
            }
            parse_main_bugreport_text(
                &text_bytes,
                opts,
                &mut metadata,
                &mut permissions_or_tables,
                &mut entries,
                &mut timeline,
            );
        } else {
            warnings.push(format!("Could not decompress main bugreport entry '{}'.", ze.name));
        }
    } else {
        warnings.push("Bugreport ZIP detected, but no bugreport-*.txt text dump was present.".to_string());
    }

    metadata.push(("Native Tombstones".to_string(), tombstones.to_string()));
    metadata.push(("ANR Traces".to_string(), anr_traces.to_string()));
    if tombstones > 0 || anr_traces > 0 {
        warnings.push(format!(
            "Bugreport archive contains {tombstones} tombstone(s) and {anr_traces} ANR trace(s) indicating app or native crashes."
        ));
    }

    ForensicReport {
        path: path.display().to_string(),
        kind: ArtifactKind::BugreportZip,
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

fn parse_main_bugreport_text(
    text_bytes: &[u8],
    opts: &ForensicOptions,
    metadata: &mut Vec<(String, String)>,
    packages_out: &mut Vec<String>,
    entries: &mut Vec<ForensicEntry>,
    timeline: &mut Vec<TimelineEvent>,
) {
    let text = String::from_utf8_lossy(text_bytes);
    let mut dumpstate_ts: Option<String> = None;
    let mut build_id: Option<String> = None;
    let mut fingerprint: Option<String> = None;
    let mut kernel: Option<String> = None;
    let mut uptime: Option<String> = None;
    let mut battery_level: Option<String> = None;

    let mut current_service = String::new();
    let mut services = BTreeSet::new();
    let mut packages = BTreeSet::new();
    let mut accounts = 0usize;
    let mut usage_events = 0usize;
    let mut wifi_ssids = 0usize;

    for raw in text.lines() {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if dumpstate_ts.is_none()
            && let Some(ts) = t.strip_prefix("== dumpstate:")
        {
            let ts_clean = ts.trim().to_string();
            if timeline.len() < opts.max_entries {
                timeline.push(TimelineEvent {
                    timestamp: normalize_space_ts_to_iso(&ts_clean).unwrap_or_else(|| ts_clean.clone()),
                    source: "Bugreport".to_string(),
                    category: "Dumpstate Header".to_string(),
                    target: "dumpstate".to_string(),
                    detail: t.to_string(),
                });
            }
            dumpstate_ts = Some(ts_clean);
            continue;
        }
        if build_id.is_none()
            && let Some(v) = t.strip_prefix("Build:")
        {
            build_id = Some(v.trim().to_string());
            continue;
        }
        if fingerprint.is_none()
            && let Some(v) = t.strip_prefix("Build fingerprint:")
        {
            fingerprint = Some(v.trim().trim_matches('\'').to_string());
            continue;
        }
        if kernel.is_none()
            && let Some(v) = t.strip_prefix("Kernel:")
        {
            kernel = Some(v.trim().to_string());
            continue;
        }
        if uptime.is_none()
            && let Some(v) = t.strip_prefix("Uptime:")
        {
            uptime = Some(v.trim().to_string());
            continue;
        }

        if let Some(svc_raw) = t.strip_prefix("DUMP OF SERVICE ") {
            let svc = svc_raw
                .trim_end_matches(':')
                .split_whitespace()
                .last()
                .unwrap_or(svc_raw)
                .to_ascii_lowercase();
            current_service = svc.clone();
            services.insert(svc);
            continue;
        }
        if t.starts_with("--------- ") && t.contains("was the duration") {
            current_service.clear();
            continue;
        }

        match current_service.as_str() {
            "package" => {
                if let Some(rest) = t.strip_prefix("Package [")
                    && let Some(end) = rest.find(']')
                {
                    let pkg = &rest[..end];
                    if packages.insert(pkg.to_string()) && entries.len() < opts.max_entries {
                        entries.push(ForensicEntry {
                            category: "Bugreport Package".to_string(),
                            name: pkg.to_string(),
                            detail: rest[end + 1..].trim().to_string(),
                            size_bytes: None,
                        });
                    }
                }
            }
            "usagestats" => {
                if let Some(raw_ts) = extract_quoted_field(t, "time=") {
                    usage_events += 1;
                    let pkg = extract_field_token(t, "package=").unwrap_or_else(|| "system".to_string());
                    let ev_type = extract_field_token(t, "type=").unwrap_or_else(|| "EVENT".to_string());
                    if entries.len() < opts.max_entries {
                        entries.push(ForensicEntry {
                            category: "UsageStats".to_string(),
                            name: pkg.clone(),
                            detail: format!("{ev_type} @ {raw_ts}"),
                            size_bytes: None,
                        });
                    }
                    if timeline.len() < opts.max_entries {
                        timeline.push(TimelineEvent {
                            timestamp: normalize_space_ts_to_iso(&raw_ts).unwrap_or(raw_ts),
                            source: "UsageStats".to_string(),
                            category: ev_type,
                            target: pkg,
                            detail: t.to_string(),
                        });
                    }
                }
            }
            "account" => {
                if let Some(start) = t.find("Account {") {
                    accounts += 1;
                    if entries.len() < opts.max_entries {
                        let snippet = t[start..].trim_end_matches('}');
                        entries.push(ForensicEntry {
                            category: "Account".to_string(),
                            name: extract_account_name(snippet),
                            detail: snippet.to_string(),
                            size_bytes: None,
                        });
                    }
                }
            }
            "battery" => {
                if battery_level.is_none()
                    && let Some(v) = t.strip_prefix("level:")
                {
                    battery_level = Some(format!("{}%", v.trim()));
                }
            }
            "wifi" if (t.starts_with("SSID:") || t.contains(" SSID: ")) => {
                wifi_ssids += 1;
            }
            _ => {}
        }
    }

    if let Some(ts) = dumpstate_ts {
        metadata.push(("Dumpstate Timestamp".to_string(), ts));
    }
    if let Some(b) = build_id {
        metadata.push(("Build ID".to_string(), b));
    }
    if let Some(fp) = fingerprint {
        metadata.push(("Build Fingerprint".to_string(), fp));
    }
    if let Some(k) = kernel {
        metadata.push(("Kernel".to_string(), k));
    }
    if let Some(u) = uptime {
        metadata.push(("Uptime".to_string(), u));
    }
    if let Some(bat) = battery_level {
        metadata.push(("Battery Level".to_string(), bat));
    }
    if wifi_ssids > 0 {
        metadata.push(("Wi-Fi SSIDs Seen".to_string(), wifi_ssids.to_string()));
    }
    metadata.push(("Dumpsys Services Parsed".to_string(), services.len().to_string()));
    metadata.push(("Packages Enumerated".to_string(), packages.len().to_string()));
    metadata.push(("Accounts Discovered".to_string(), accounts.to_string()));
    metadata.push(("UsageStats Events".to_string(), usage_events.to_string()));
    packages_out.extend(packages);
}

fn extract_quoted_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}\"");
    let start = line.find(&needle)? + needle.len();
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_string())
}

fn extract_field_token(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let rest = line[start..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find(|c: char| c.is_whitespace() || c == ')').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

fn extract_account_name(snippet: &str) -> String {
    if let Some(start) = snippet.find("name=") {
        let rest = &snippet[start + 5..];
        let end = rest.find(',').unwrap_or(rest.len());
        return rest[..end].trim().to_string();
    }
    "Account".to_string()
}

fn normalize_space_ts_to_iso(raw: &str) -> Option<String> {
    // Converts "YYYY-MM-DD HH:MM:SS" (plus optional fractional seconds) into "YYYY-MM-DDTHH:MM:SSZ"
    let s = raw.trim();
    if s.len() >= 19 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-' && s.as_bytes()[10] == b' ' {
        let date_time = &s[..19];
        return Some(format!("{}Z", date_time.replacen(' ', "T", 1)));
    }
    None
}
