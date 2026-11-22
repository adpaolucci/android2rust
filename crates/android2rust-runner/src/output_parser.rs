use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileActionKind {
    Device,
    Property,
    Package,
    Transfer,
    Logcat,
    Fastboot,
    Forensic,
    Error,
}

impl FileActionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Device => "Device",
            Self::Property => "Property",
            Self::Package => "Package",
            Self::Transfer => "Transfer",
            Self::Logcat => "Logcat",
            Self::Fastboot => "Fastboot",
            Self::Forensic => "Forensic",
            Self::Error => "Error",
        }
    }

    pub fn is_transfer_or_forensic(self) -> bool {
        matches!(self, Self::Transfer | Self::Forensic)
    }

    pub fn is_device_or_pkg(self) -> bool {
        matches!(self, Self::Device | Self::Package | Self::Property)
    }

    pub fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileActionRecord {
    pub kind: FileActionKind,
    pub path: String,
    pub detail: String,
    pub size_bytes: Option<u64>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RunSummary {
    pub devices_seen: u64,
    pub properties_seen: u64,
    pub packages_seen: u64,
    pub files_transferred: u64,
    pub bytes_processed: u64,
    pub log_lines_seen: u64,
    pub errors_seen: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParsedLineOutcome {
    Ignored,
    Progress(f32),
    Record(FileActionRecord),
    Error(String),
    Plain,
}

static RE_PCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[\s*(\d{1,3})%\]").unwrap());
static RE_LOGCAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^((?:\d{4}-)?\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+\d+\s+\d+\s+([VDIWEFA])\s+(.*)$").unwrap()
});
static RE_PULL_SUMMARY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+)\s+files?\s+(?:pulled|pushed).*?\((\d+)\s+bytes").unwrap());

#[derive(Debug, Default)]
pub struct AndroidOutputParser {
    pub summary: RunSummary,
    pub current_item: Option<String>,
    pub detected_status_tokens: Vec<String>,
}

impl AndroidOutputParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed_line(&mut self, raw: &str) -> ParsedLineOutcome {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return ParsedLineOutcome::Ignored;
        }
        self.summary.log_lines_seen += 1;

        for marker in ["INSTALL_FAILED_", "INSTALL_PARSE_FAILED_", "DELETE_FAILED_"] {
            if let Some(pos) = trimmed.find(marker) {
                let token: String = trimmed[pos..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !token.is_empty() && !self.detected_status_tokens.iter().any(|t| t == &token) {
                    self.detected_status_tokens.push(token);
                }
            }
        }

        let lower = trimmed.to_ascii_lowercase();
        let mut push_tok = |tok: &str| {
            if !self.detected_status_tokens.iter().any(|t| t == tok) {
                self.detected_status_tokens.push(tok.to_string());
            }
        };
        if lower.contains("device unauthorized") || trimmed.contains("DEVICE_UNAUTHORIZED") {
            push_tok("DEVICE_UNAUTHORIZED");
        }
        if lower.contains("device offline") || trimmed.contains("DEVICE_OFFLINE") {
            push_tok("DEVICE_OFFLINE");
        }
        if lower.contains("no devices/emulators found")
            || (lower.contains("device '") && lower.contains("' not found"))
            || trimmed.contains("NO_DEVICES_FOUND")
        {
            push_tok("NO_DEVICES_FOUND");
        }
        if lower.contains("flashing is not allowed")
            || lower.contains("device is locked")
            || lower.contains("bootloader is locked")
            || trimmed.contains("FASTBOOT_LOCKED")
        {
            push_tok("FASTBOOT_LOCKED");
        }
        if lower.contains("no such partition")
            || lower.contains("partition doesn't exist")
            || lower.contains("partition table doesn't exist")
            || trimmed.contains("FASTBOOT_PARTITION_NOT_FOUND")
        {
            push_tok("FASTBOOT_PARTITION_NOT_FOUND");
        }

        if let Some(cap) = RE_PCT.captures(trimmed)
            && let Ok(pct) = cap[1].parse::<f32>()
        {
            if let Some(after) = trimmed.split(']').nth(1) {
                let item = after.trim();
                if !item.is_empty() {
                    self.current_item = Some(item.to_string());
                }
            }
            return ParsedLineOutcome::Progress(pct.clamp(0.0, 100.0));
        }

        if let Some(cap) = RE_PULL_SUMMARY.captures(trimmed) {
            if let Ok(files) = cap[1].parse::<u64>() {
                self.summary.files_transferred += files;
            }
            if let Ok(bytes) = cap[2].parse::<u64>() {
                self.summary.bytes_processed += bytes;
            }
            let rec = FileActionRecord {
                kind: FileActionKind::Transfer,
                path: self.current_item.clone().unwrap_or_else(|| "Transfer".to_string()),
                detail: trimmed.to_string(),
                size_bytes: cap[2].parse().ok(),
                timestamp: None,
            };
            return ParsedLineOutcome::Record(rec);
        }

        // adb shell getprop: [ro.build.version.release]: [15]
        if trimmed.starts_with('[')
            && let Some((k, v)) = trimmed.split_once("]: [")
        {
            self.summary.properties_seen += 1;
            let key = k.trim_start_matches('[').to_string();
            let val = v.trim_end_matches(']').to_string();
            return ParsedLineOutcome::Record(FileActionRecord {
                kind: FileActionKind::Property,
                path: key,
                detail: val,
                size_bytes: None,
                timestamp: None,
            });
        }

        // adb shell pm list packages
        if let Some(rest) = trimmed.strip_prefix("package:") {
            self.summary.packages_seen += 1;
            return ParsedLineOutcome::Record(FileActionRecord {
                kind: FileActionKind::Package,
                path: rest.trim().to_string(),
                detail: "Installed package".to_string(),
                size_bytes: None,
                timestamp: None,
            });
        }

        // adb devices -l or fastboot devices line
        if !trimmed.starts_with("List of devices")
            && !trimmed.starts_with('*')
            && (trimmed.contains("\tdevice")
                || trimmed.contains(" device ")
                || trimmed.contains(" unauthorized")
                || trimmed.contains(" offline")
                || trimmed.contains("\tfastboot")
                || trimmed.contains(" fastboot"))
        {
            self.summary.devices_seen += 1;
            let mut parts = trimmed.split_whitespace();
            let serial = parts.next().unwrap_or(trimmed).to_string();
            let detail = parts.collect::<Vec<_>>().join(" ");
            return ParsedLineOutcome::Record(FileActionRecord {
                kind: FileActionKind::Device,
                path: serial,
                detail,
                size_bytes: None,
                timestamp: None,
            });
        }

        // Logcat threadtime
        if let Some(cap) = RE_LOGCAT.captures(trimmed) {
            let ts = cap[1].to_string();
            let level = &cap[2];
            let msg = cap[3].to_string();
            if matches!(level, "E" | "F") {
                self.summary.errors_seen += 1;
            }
            return ParsedLineOutcome::Record(FileActionRecord {
                kind: if matches!(level, "E" | "F") {
                    FileActionKind::Error
                } else {
                    FileActionKind::Logcat
                },
                path: format!("{level}/logcat"),
                detail: msg,
                size_bytes: None,
                timestamp: Some(ts),
            });
        }

        // Fastboot lines
        if trimmed.starts_with("Sending '")
            || trimmed.starts_with("Writing '")
            || trimmed.starts_with("Erasing '")
            || trimmed.starts_with("(bootloader) ")
        {
            let detail = trimmed.strip_prefix("(bootloader) ").unwrap_or(trimmed).to_string();
            return ParsedLineOutcome::Record(FileActionRecord {
                kind: FileActionKind::Fastboot,
                path: "fastboot".to_string(),
                detail,
                size_bytes: None,
                timestamp: None,
            });
        }

        if trimmed.starts_with("Failure [")
            || trimmed.starts_with("FAILED (")
            || trimmed.starts_with("adb: error:")
            || trimmed.starts_with("error:")
        {
            self.summary.errors_seen += 1;
            return ParsedLineOutcome::Error(trimmed.to_string());
        }

        ParsedLineOutcome::Plain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_devices_props_packages_and_progress() {
        let mut p = AndroidOutputParser::new();
        match p.feed_line("R58M123456\tdevice product:panther model:Pixel_7") {
            ParsedLineOutcome::Record(r) => {
                assert_eq!(r.kind, FileActionKind::Device);
                assert_eq!(r.path, "R58M123456");
            }
            other => panic!("unexpected: {other:?}"),
        }

        assert!(matches!(
            p.feed_line("[ro.build.version.release]: [15]"),
            ParsedLineOutcome::Record(_)
        ));
        assert!(matches!(
            p.feed_line("package:/data/app/base.apk=com.example.demo"),
            ParsedLineOutcome::Record(_)
        ));
        assert_eq!(
            p.feed_line("[ 42%] /sdcard/DCIM/IMG_001.jpg"),
            ParsedLineOutcome::Progress(42.0)
        );
        assert_eq!(p.summary.devices_seen, 1);
        assert_eq!(p.summary.properties_seen, 1);
        assert_eq!(p.summary.packages_seen, 1);
    }

    #[test]
    fn detects_real_adb_and_fastboot_error_tokens() {
        let mut p = AndroidOutputParser::new();
        p.feed_line("adb.exe: error: device unauthorized.");
        p.feed_line("error: no devices/emulators found");
        p.feed_line("Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES]");
        p.feed_line("FAILED (remote: 'Flashing is not allowed in Lock State')");

        assert_eq!(
            p.detected_status_tokens,
            vec![
                "DEVICE_UNAUTHORIZED".to_string(),
                "NO_DEVICES_FOUND".to_string(),
                "INSTALL_PARSE_FAILED_NO_CERTIFICATES".to_string(),
                "FASTBOOT_LOCKED".to_string(),
            ]
        );
    }
}
