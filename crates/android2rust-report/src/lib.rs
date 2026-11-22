#![forbid(unsafe_code)]

pub mod html;
pub mod json;
pub mod markdown;
pub mod timeline;

use android2rust_core::{AndroidJob, AndroidOperation, ForensicOptions, ToolFamily, decode_exit_code};
use android2rust_runner::{AndroidOutputParser, CancelToken, ParsedLineOutcome, RunResult, run_job_blocking};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Html,
    Json,
    Markdown,
    TimelineCsv,
    TimelineJsonl,
    All,
}

impl ReportFormat {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "html" | "htm" => Ok(Self::Html),
            "json" => Ok(Self::Json),
            "md" | "markdown" => Ok(Self::Markdown),
            "csv" | "timeline-csv" => Ok(Self::TimelineCsv),
            "jsonl" | "ndjson" | "timeline-jsonl" => Ok(Self::TimelineJsonl),
            "all" | "bundle" => Ok(Self::All),
            other => anyhow::bail!(
                "Unsupported report format '{other}'. Use html, json, markdown, timeline-csv, timeline-jsonl, or all."
            ),
        }
    }
}

pub fn write_report(result: &RunResult, format: ReportFormat, output: &Path) -> Result<Vec<PathBuf>> {
    let mut written = Vec::new();
    match format {
        ReportFormat::Html => {
            ensure_parent(output)?;
            std::fs::write(output, html::render_html(result))?;
            written.push(output.to_path_buf());
        }
        ReportFormat::Json => {
            ensure_parent(output)?;
            std::fs::write(output, json::render_json(result)?)?;
            written.push(output.to_path_buf());
        }
        ReportFormat::Markdown => {
            ensure_parent(output)?;
            std::fs::write(output, markdown::render_markdown(result))?;
            written.push(output.to_path_buf());
        }
        ReportFormat::TimelineCsv => {
            ensure_parent(output)?;
            std::fs::write(output, timeline::render_timeline_csv(result))?;
            written.push(output.to_path_buf());
        }
        ReportFormat::TimelineJsonl => {
            ensure_parent(output)?;
            std::fs::write(output, timeline::render_timeline_jsonl(result)?)?;
            written.push(output.to_path_buf());
        }
        ReportFormat::All => {
            let dir = if output.extension().is_some() {
                output.parent().unwrap_or_else(|| Path::new("."))
            } else {
                output
            };
            std::fs::create_dir_all(dir)?;
            let stem = output
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|_| output.extension().is_some())
                .unwrap_or("android2rust_report");

            let html_path = dir.join(format!("{stem}.html"));
            let json_path = dir.join(format!("{stem}.json"));
            let md_path = dir.join(format!("{stem}.md"));

            std::fs::write(&html_path, html::render_html(result))?;
            std::fs::write(&json_path, json::render_json(result)?)?;
            std::fs::write(&md_path, markdown::render_markdown(result))?;
            written.push(html_path);
            written.push(json_path);
            written.push(md_path);
        }
    }
    Ok(written)
}

pub fn write_timeline(result: &RunResult, output: &Path) -> Result<PathBuf> {
    let is_jsonl = output
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "jsonl" | "ndjson"));
    let fmt = if is_jsonl {
        ReportFormat::TimelineJsonl
    } else {
        ReportFormat::TimelineCsv
    };
    let mut written = write_report(result, fmt, output)?;
    Ok(written.pop().unwrap_or_else(|| output.to_path_buf()))
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Imports an existing ADB/Fastboot text log OR a binary Android artifact (`.apk`, `.ab`, `.db`, `ABX`, `.xml`, dir)
/// into a structured [`RunResult`] ready for HTML/JSON/Markdown/Timeline report export.
pub fn parse_log_file_to_run_result(path: &Path) -> Result<RunResult> {
    parse_log_file_with_options(path, ForensicOptions::default())
}

pub fn parse_log_file_with_options(path: &Path, opts: ForensicOptions) -> Result<RunResult> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if path.is_dir() || matches!(ext.as_str(), "apk" | "ab" | "db" | "sqlite" | "sqlite3" | "xml" | "abx") {
        let job = AndroidJob {
            name: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("Artifact Inspection")
                .to_string(),
            tool: ToolFamily::Forensics,
            operation: AndroidOperation::InspectArtifact,
            source_path: path.display().to_string(),
            forensic_opts: opts,
            ..Default::default()
        };
        return run_job_blocking(&job, None, &CancelToken::new());
    }

    let mut head_file =
        std::fs::File::open(path).with_context(|| format!("Failed to open log file {}", path.display()))?;
    let mut head = [0u8; 64];
    let mut head_len = 0usize;
    while head_len < head.len() {
        match std::io::Read::read(&mut head_file, &mut head[head_len..]) {
            Ok(0) => break,
            Ok(n) => head_len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).with_context(|| format!("Failed to inspect header of {}", path.display())),
        }
    }
    drop(head_file);

    let sig = &head[..head_len];
    if sig.starts_with(b"ANDROID BACKUP\n")
        || sig.starts_with(b"ANDROID BACKUP\r\n")
        || sig.starts_with(b"SQLite format 3\0")
        || sig.starts_with(b"PK\x03\x04")
        || sig.starts_with(b"PK\x05\x06")
        || sig.starts_with(b"dex\n")
        || sig.starts_with(b"ABX\0")
        || (head_len >= 8 && sig.starts_with(&[0x03, 0x00, 0x08, 0x00]))
    {
        let job = AndroidJob {
            name: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("Artifact Inspection")
                .to_string(),
            tool: ToolFamily::Forensics,
            operation: AndroidOperation::InspectArtifact,
            source_path: path.display().to_string(),
            forensic_opts: opts,
            ..Default::default()
        };
        return run_job_blocking(&job, None, &CancelToken::new());
    }

    let bytes = std::fs::read(path).with_context(|| format!("Failed to read log file {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let mut parser = AndroidOutputParser::new();
    let mut file_actions = Vec::new();
    let mut errors = Vec::new();
    let mut log_lines = Vec::new();
    let mut hasher = Sha256::new();
    let mut hasher512 = Sha512::new();

    for raw in text.lines() {
        let line = raw.trim_end_matches('\r').to_string();
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
        hasher512.update(line.as_bytes());
        hasher512.update(b"\n");
        log_lines.push(line.clone());

        match parser.feed_line(&line) {
            ParsedLineOutcome::Record(rec) => file_actions.push(rec),
            ParsedLineOutcome::Error(e) => errors.push(e),
            _ => {}
        }
    }

    let code = if errors.is_empty() { 0 } else { 1 };
    let now = Utc::now().to_rfc3339();
    Ok(RunResult {
        job_name: path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("Imported Android Log")
            .to_string(),
        tool: ToolFamily::Adb,
        operation: AndroidOperation::Logcat,
        source: path.display().to_string(),
        destination: String::new(),
        dry_run: false,
        command_line: format!("android2rust report --log-file \"{}\"", path.display()),
        args: Vec::new(),
        started_at: now.clone(),
        ended_at: now,
        duration_secs: 0.0,
        exit_code: code,
        status_info: decode_exit_code(code),
        cancelled: false,
        summary: parser.summary,
        file_actions,
        forensic_report: None,
        errors,
        log_lines,
        log_sha256: android2rust_core::format::encode_hex_lower(&hasher.finalize()),
        log_sha512: android2rust_core::format::encode_hex_lower(&hasher512.finalize()),
        case_meta: opts.case_meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use android2rust_core::CaseMetadata;
    use tempfile::TempDir;

    #[test]
    fn parses_android_log_and_writes_air_gapped_bundle() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("android.log");
        let content = "\
List of devices attached
R58M123456\tdevice product:panther model:Pixel_7
[ro.build.version.release]: [15]
package:/data/app/base.apk=com.example.chat
11-19 12:00:01.123  1000  1001 E ActivityManager: ANR in com.example.chat
";
        std::fs::write(&log_path, content).unwrap();

        let opts = ForensicOptions {
            case_meta: CaseMetadata {
                case_id: Some("IR-2026-09".to_string()),
                evidence_id: Some("PIXEL-01".to_string()),
                examiner: Some("J. Doe".to_string()),
            },
            ..Default::default()
        };
        let parsed = parse_log_file_with_options(&log_path, opts).unwrap();
        assert_eq!(parsed.summary.devices_seen, 1);
        assert_eq!(parsed.summary.properties_seen, 1);
        assert_eq!(parsed.summary.packages_seen, 1);
        assert_eq!(parsed.summary.errors_seen, 1);
        assert_eq!(parsed.log_sha256.len(), 64);
        assert_eq!(parsed.log_sha512.len(), 128);

        let bundle_dir = tmp.path().join("bundle");
        let written = write_report(&parsed, ReportFormat::All, &bundle_dir).unwrap();
        assert_eq!(written.len(), 3);

        let html = std::fs::read_to_string(&written[0]).unwrap();
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("https://cdn"));
        assert!(!html.contains("<script src="));
        assert!(html.contains("Pixel_7"));
        assert!(html.contains("IR-2026-09"));
        assert!(html.contains(&parsed.log_sha256));
        assert!(html.contains(&parsed.log_sha512));

        let md = std::fs::read_to_string(&written[2]).unwrap();
        assert!(md.contains("IR-2026-09"));
        assert!(md.contains(&parsed.log_sha512));

        // Timeline CSV & JSONL export on timestamped logcat dump
        let logcat_path = tmp.path().join("events.txt");
        std::fs::write(
            &logcat_path,
            "2025-05-01 09:00:00.100  1000  1001 E BootCheck: failure\n",
        )
        .unwrap();
        let tl_res = parse_log_file_to_run_result(&logcat_path).unwrap();
        let csv_path = write_timeline(&tl_res, &tmp.path().join("tl.csv")).unwrap();
        let csv = std::fs::read_to_string(csv_path).unwrap();
        assert!(csv.starts_with("timestamp,source,category,target,detail\n"));
        assert!(csv.contains("2025-05-01T09:00:00.100Z,Run Telemetry,Error,E/logcat,BootCheck: failure"));

        let jsonl_path = write_timeline(&tl_res, &tmp.path().join("tl.jsonl")).unwrap();
        let jsonl = std::fs::read_to_string(jsonl_path).unwrap();
        assert!(jsonl.contains("\"timestamp\":\"2025-05-01T09:00:00.100Z\""));

        let prefs_path = tmp.path().join("prefs.xml");
        std::fs::write(
            &prefs_path,
            r#"<map><long name="last_sync" value="1700000000000"/></map>"#,
        )
        .unwrap();
        let prefs_res = parse_log_file_to_run_result(&prefs_path).unwrap();
        let prefs_csv_path = write_timeline(&prefs_res, &tmp.path().join("prefs_tl.csv")).unwrap();
        let prefs_csv = std::fs::read_to_string(prefs_csv_path).unwrap();
        assert!(prefs_csv.contains("SharedPrefs,Preference Epoch,last_sync"));
    }
}
