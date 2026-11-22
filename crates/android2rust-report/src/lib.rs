#![forbid(unsafe_code)]

pub mod html;
pub mod json;
pub mod markdown;

use android2rust_core::{AndroidJob, AndroidOperation, ToolFamily, decode_exit_code};
use android2rust_runner::{AndroidOutputParser, CancelToken, ParsedLineOutcome, RunResult, run_job_blocking};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Html,
    Json,
    Markdown,
    All,
}

impl ReportFormat {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "html" | "htm" => Ok(Self::Html),
            "json" => Ok(Self::Json),
            "md" | "markdown" => Ok(Self::Markdown),
            "all" | "bundle" => Ok(Self::All),
            other => anyhow::bail!("Unsupported report format '{other}'. Use html, json, markdown, or all."),
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

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Imports an existing ADB/Fastboot text log OR a binary Android artifact (`.apk`, `.ab`, `.db`, `.xml`, dir)
/// into a structured [`RunResult`] ready for HTML/JSON/Markdown report export.
pub fn parse_log_file_to_run_result(path: &Path) -> Result<RunResult> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if path.is_dir() || matches!(ext.as_str(), "apk" | "ab" | "db" | "sqlite" | "sqlite3" | "xml") {
        let job = AndroidJob {
            name: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("Artifact Inspection")
                .to_string(),
            tool: ToolFamily::Forensics,
            operation: AndroidOperation::InspectArtifact,
            source_path: path.display().to_string(),
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

    for raw in text.lines() {
        let line = raw.trim_end_matches('\r').to_string();
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let parsed = parse_log_file_to_run_result(&log_path).unwrap();
        assert_eq!(parsed.summary.devices_seen, 1);
        assert_eq!(parsed.summary.properties_seen, 1);
        assert_eq!(parsed.summary.packages_seen, 1);
        assert_eq!(parsed.summary.errors_seen, 1);

        let bundle_dir = tmp.path().join("bundle");
        let written = write_report(&parsed, ReportFormat::All, &bundle_dir).unwrap();
        assert_eq!(written.len(), 3);

        let html = std::fs::read_to_string(&written[0]).unwrap();
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("https://cdn"));
        assert!(!html.contains("<script src="));
        assert!(html.contains("Pixel_7"));
        assert!(html.contains(&parsed.log_sha256));
    }
}
