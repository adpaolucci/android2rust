use crate::env::{find_adb_executable, find_fastboot_executable};
use crate::output_parser::{AndroidOutputParser, FileActionKind, FileActionRecord, ParsedLineOutcome, RunSummary};
use android2rust_core::{
    AndroidJob, AndroidOperation, CaseMetadata, ForensicReport, StatusCodeInfo, StatusSeverity, ToolFamily, build_args,
    decode_exit_code, decode_status_code, format_command_line, inspect_artifact, validate_job,
};
use android2rust_wpd::{
    CopyOutOptions, DirectoryMtpSource, LiveWpdSource, MobileFileQuery, MtpDeviceSource, WpdError, copy_out,
    search_devices,
};
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub job_name: String,
    pub tool: ToolFamily,
    pub operation: AndroidOperation,
    pub source: String,
    pub destination: String,
    pub dry_run: bool,
    pub command_line: String,
    pub args: Vec<String>,
    pub started_at: String,
    pub ended_at: String,
    pub duration_secs: f64,
    pub exit_code: i32,
    pub status_info: StatusCodeInfo,
    pub cancelled: bool,
    pub summary: RunSummary,
    pub file_actions: Vec<FileActionRecord>,
    pub forensic_report: Option<ForensicReport>,
    pub errors: Vec<String>,
    pub log_lines: Vec<String>,
    pub log_sha256: String,
    #[serde(default)]
    pub log_sha512: String,
    #[serde(default)]
    pub case_meta: CaseMetadata,
}

#[derive(Debug, Clone)]
pub enum RunnerEvent {
    Started { command_line: String },
    LogLine(String),
    FileAction(FileActionRecord),
    Progress { percent: f32, current_file: Option<String> },
    Error(String),
    Summary(RunSummary),
    Finished(Box<RunResult>),
}

type KillCallback = Box<dyn FnMut() + Send>;

#[derive(Clone, Default)]
pub struct CancelToken {
    cancelled: Arc<AtomicBool>,
    child_pid: Arc<Mutex<Option<u32>>>,
    killer: Arc<Mutex<Option<KillCallback>>>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.killer.lock()
            && let Some(mut kill_fn) = guard.take()
        {
            kill_fn();
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child_pid.lock().ok().and_then(|g| *g)
    }
}

pub fn spawn_job_runner(job: AndroidJob, binary_override: Option<PathBuf>) -> (Receiver<RunnerEvent>, CancelToken) {
    let (tx, rx) = mpsc::channel();
    let cancel = CancelToken::new();
    let cancel_worker = cancel.clone();

    std::thread::spawn(move || {
        let res = execute_job_internal(&job, binary_override.as_deref(), &cancel_worker, |ev| {
            let _ = tx.send(ev);
        });
        match res {
            Ok(final_res) => {
                let _ = tx.send(RunnerEvent::Finished(Box::new(final_res)));
            }
            Err(err) => {
                let now = Utc::now().to_rfc3339();
                let err_msg = err.to_string();
                let _ = tx.send(RunnerEvent::Error(err_msg.clone()));
                let mut hasher = Sha256::new();
                hasher.update(err_msg.as_bytes());
                let digest = android2rust_core::format::encode_hex_lower(&hasher.finalize());
                let mut hasher512 = Sha512::new();
                hasher512.update(err_msg.as_bytes());
                let digest512 = android2rust_core::format::encode_hex_lower(&hasher512.finalize());
                let (_, args) = build_args(&job);
                let is_forensics =
                    job.operation == AndroidOperation::InspectArtifact || job.tool == ToolFamily::Forensics;
                let is_wpd = job.operation == AndroidOperation::MobileFileSearch || job.tool == ToolFamily::Wpd;
                let (exit_code, status_info) = if is_forensics {
                    (
                        1,
                        StatusCodeInfo {
                            code: "1".to_string(),
                            exit_code: Some(1),
                            severity: StatusSeverity::Error,
                            is_success: false,
                            short_label: "1 (Forensic Inspection Error)".to_string(),
                            summary: err_msg.clone(),
                            details: vec![err_msg.clone()],
                        },
                    )
                } else if is_wpd {
                    (
                        1,
                        StatusCodeInfo {
                            code: "1".to_string(),
                            exit_code: Some(1),
                            severity: StatusSeverity::Error,
                            is_success: false,
                            short_label: "1 (WPD/MTP Search Error)".to_string(),
                            summary: err_msg.clone(),
                            details: vec![err_msg.clone()],
                        },
                    )
                } else if err_msg.contains("was not found on PATH") || err_msg.starts_with("Failed to launch ") {
                    (127, decode_exit_code(127))
                } else {
                    (
                        1,
                        StatusCodeInfo {
                            code: "1".to_string(),
                            exit_code: Some(1),
                            severity: StatusSeverity::Error,
                            is_success: false,
                            short_label: "1 (Execution Error)".to_string(),
                            summary: err_msg.clone(),
                            details: vec![err_msg.clone()],
                        },
                    )
                };
                let fallback = RunResult {
                    job_name: job.name.clone(),
                    tool: job.tool,
                    operation: job.operation,
                    source: job.source_path.clone(),
                    destination: job.target_path.clone(),
                    dry_run: job.dry_run,
                    command_line: format_command_line(&job),
                    args,
                    started_at: now.clone(),
                    ended_at: now,
                    duration_secs: 0.0,
                    exit_code,
                    status_info,
                    cancelled: cancel_worker.is_cancelled(),
                    summary: RunSummary {
                        errors_seen: 1,
                        ..Default::default()
                    },
                    file_actions: Vec::new(),
                    forensic_report: None,
                    errors: vec![err_msg.clone()],
                    log_lines: vec![err_msg],
                    log_sha256: digest,
                    log_sha512: digest512,
                    case_meta: job.forensic_opts.case_meta.clone(),
                };
                let _ = tx.send(RunnerEvent::Finished(Box::new(fallback)));
            }
        }
    });

    (rx, cancel)
}

pub fn run_job_blocking(job: &AndroidJob, binary_override: Option<&Path>, cancel: &CancelToken) -> Result<RunResult> {
    execute_job_internal(job, binary_override, cancel, |_| {})
}

fn execute_job_internal(
    job: &AndroidJob,
    binary_override: Option<&Path>,
    cancel: &CancelToken,
    mut emit: impl FnMut(RunnerEvent),
) -> Result<RunResult> {
    let (_, args) = build_args(job);
    let command_line = format_command_line(job);
    let started_at = Utc::now().to_rfc3339();
    let timer = Instant::now();

    emit(RunnerEvent::Started {
        command_line: command_line.clone(),
    });

    // 1. Offline Forensic Inspection runs 100% in pure Rust without adb/fastboot binaries
    if job.operation == AndroidOperation::InspectArtifact || job.tool == ToolFamily::Forensics {
        return execute_forensic_job(job, &args, &command_line, &started_at, timer, &mut emit);
    }

    // 2. Dry-Run Pre-Flight Simulation (never modifies connected Android hardware)
    if job.dry_run {
        return execute_dry_run_simulation(job, &args, &command_line, &started_at, timer, &mut emit);
    }

    // 2b. WPD / MTP File Search (Windows COM or offline directory fixture)
    if job.operation == AndroidOperation::MobileFileSearch || job.tool == ToolFamily::Wpd {
        return execute_wpd_job(job, &args, &command_line, &started_at, timer, &mut emit);
    }

    // 3. Live ADB / Fastboot Execution
    let binary = resolve_binary(job, binary_override)?;
    let mut cmd = build_process_command(&binary, &args);
    let mut child: Child = cmd
        .spawn()
        .with_context(|| format!("Failed to launch {}", binary.display()))?;

    let pid = child.id();
    if let Ok(mut g) = cancel.child_pid.lock() {
        *g = Some(pid);
    }
    if let Ok(mut k) = cancel.killer.lock() {
        *k = Some(Box::new(move || {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T", "/F"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .output();
            }
            #[cfg(not(windows))]
            {
                let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).output();
            }
        }));
    }
    if cancel.is_cancelled() {
        cancel.cancel();
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (line_tx, line_rx) = mpsc::channel::<(bool, String)>();

    let stdout_handle = stdout.map(|out| {
        let tx = line_tx.clone();
        std::thread::spawn(move || stream_lines(out, false, tx))
    });
    let stderr_handle = stderr.map(|err| {
        let tx = line_tx.clone();
        std::thread::spawn(move || stream_lines(err, true, tx))
    });
    drop(line_tx);

    const MAX_LIVE_LOG_LINES: usize = 200_000;
    const MAX_LIVE_FILE_ACTIONS: usize = 200_000;
    const MAX_LIVE_ERRORS: usize = 10_000;

    let mut parser = AndroidOutputParser::new();
    let mut file_actions = Vec::new();
    let mut errors = Vec::new();
    let mut log_lines = Vec::new();
    let mut hasher = Sha256::new();
    let mut hasher512 = Sha512::new();

    for (is_err, line) in line_rx {
        if cancel.is_cancelled() {
            let _ = child.kill();
        }
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
        hasher512.update(line.as_bytes());
        hasher512.update(b"\n");

        if is_err {
            if !line.trim().is_empty() {
                // Fastboot writes progress & info to stderr normally
                let outcome = parser.feed_line(&line);
                match outcome {
                    ParsedLineOutcome::Progress(pct) => {
                        emit(RunnerEvent::Progress {
                            percent: pct,
                            current_file: parser.current_item.clone(),
                        });
                    }
                    ParsedLineOutcome::Record(rec) => {
                        if log_lines.len() < MAX_LIVE_LOG_LINES {
                            log_lines.push(line);
                        }
                        if file_actions.len() < MAX_LIVE_FILE_ACTIONS {
                            file_actions.push(rec.clone());
                        }
                        emit(RunnerEvent::FileAction(rec));
                        emit(RunnerEvent::Summary(parser.summary.clone()));
                    }
                    ParsedLineOutcome::Error(err_txt) => {
                        if errors.len() < MAX_LIVE_ERRORS {
                            errors.push(err_txt.clone());
                        }
                        if log_lines.len() < MAX_LIVE_LOG_LINES {
                            log_lines.push(format!("[stderr] {line}"));
                        }
                        emit(RunnerEvent::Error(err_txt));
                        emit(RunnerEvent::Summary(parser.summary.clone()));
                    }
                    _ => {
                        if log_lines.len() < MAX_LIVE_LOG_LINES {
                            log_lines.push(format!("[stderr] {line}"));
                        }
                        emit(RunnerEvent::LogLine(line));
                    }
                }
            }
            continue;
        }

        let outcome = parser.feed_line(&line);
        match outcome {
            ParsedLineOutcome::Progress(pct) => {
                emit(RunnerEvent::Progress {
                    percent: pct,
                    current_file: parser.current_item.clone(),
                });
            }
            ParsedLineOutcome::Record(rec) => {
                if log_lines.len() < MAX_LIVE_LOG_LINES {
                    log_lines.push(line);
                }
                if file_actions.len() < MAX_LIVE_FILE_ACTIONS {
                    file_actions.push(rec.clone());
                }
                emit(RunnerEvent::FileAction(rec));
                emit(RunnerEvent::Summary(parser.summary.clone()));
            }
            ParsedLineOutcome::Error(err_txt) => {
                if log_lines.len() < MAX_LIVE_LOG_LINES {
                    log_lines.push(line);
                }
                if errors.len() < MAX_LIVE_ERRORS {
                    errors.push(err_txt.clone());
                }
                emit(RunnerEvent::Error(err_txt));
                emit(RunnerEvent::Summary(parser.summary.clone()));
            }
            _ => {
                if log_lines.len() < MAX_LIVE_LOG_LINES {
                    log_lines.push(line.clone());
                }
                emit(RunnerEvent::LogLine(line));
            }
        }
    }

    if let Some(h) = stdout_handle {
        let _ = h.join();
    }
    if let Some(h) = stderr_handle {
        let _ = h.join();
    }

    let status = child.wait()?;
    if let Ok(mut k) = cancel.killer.lock() {
        *k = None;
    }
    if let Ok(mut g) = cancel.child_pid.lock() {
        *g = None;
    }

    let cancelled = cancel.is_cancelled();
    let exit_code = if cancelled { -1 } else { status.code().unwrap_or(1) };
    let allow_token_override = !cancelled
        && (exit_code != 0
            || matches!(
                job.operation,
                AndroidOperation::InstallApk
                    | AndroidOperation::UninstallPackage
                    | AndroidOperation::Sideload
                    | AndroidOperation::FastbootFlash
                    | AndroidOperation::FastbootErase
                    | AndroidOperation::FastbootFormat
                    | AndroidOperation::FastbootFlashingUnlock
                    | AndroidOperation::FastbootFlashingLock
            ));
    let status_info = if allow_token_override && let Some(tok) = parser.detected_status_tokens.first() {
        let mut decoded = decode_status_code(tok);
        decoded.exit_code = Some(exit_code);
        decoded
    } else {
        decode_exit_code(exit_code)
    };

    Ok(RunResult {
        job_name: job.name.clone(),
        tool: job.tool,
        operation: job.operation,
        source: job.source_path.clone(),
        destination: job.target_path.clone(),
        dry_run: false,
        command_line,
        args,
        started_at,
        ended_at: Utc::now().to_rfc3339(),
        duration_secs: timer.elapsed().as_secs_f64(),
        exit_code,
        status_info,
        cancelled,
        summary: parser.summary,
        file_actions,
        forensic_report: None,
        errors,
        log_lines,
        log_sha256: android2rust_core::format::encode_hex_lower(&hasher.finalize()),
        log_sha512: android2rust_core::format::encode_hex_lower(&hasher512.finalize()),
        case_meta: job.forensic_opts.case_meta.clone(),
    })
}

fn execute_forensic_job(
    job: &AndroidJob,
    args: &[String],
    command_line: &str,
    started_at: &str,
    timer: Instant,
    emit: &mut impl FnMut(RunnerEvent),
) -> Result<RunResult> {
    let artifact_path = Path::new(job.source_path.trim());
    if job.source_path.trim().is_empty() {
        return Err(anyhow!("No artifact path specified for forensic inspection."));
    }
    let report = inspect_artifact(artifact_path, &job.forensic_opts)?;

    let mut log_lines = vec![
        format!("Artifact: {}", report.path),
        format!("Detected Format: {}", report.kind.label()),
        format!("Size: {} bytes", report.total_bytes),
        format!("SHA-256: {}", report.sha256),
        format!("SHA-512: {}", report.sha512),
    ];
    for (k, v) in &report.metadata {
        log_lines.push(format!("{k}: {v}"));
    }
    for perm in &report.permissions_or_tables {
        log_lines.push(format!("Schema/Permission: {perm}"));
    }

    let mut file_actions = Vec::with_capacity(report.entries.len() + report.metadata.len());
    for (k, v) in &report.metadata {
        let rec = FileActionRecord {
            kind: FileActionKind::Property,
            path: k.clone(),
            detail: v.clone(),
            size_bytes: None,
            timestamp: None,
        };
        emit(RunnerEvent::FileAction(rec.clone()));
        file_actions.push(rec);
    }
    for p in &report.permissions_or_tables {
        let rec = FileActionRecord {
            kind: FileActionKind::Forensic,
            path: "Manifest/Schema".to_string(),
            detail: p.clone(),
            size_bytes: None,
            timestamp: None,
        };
        emit(RunnerEvent::FileAction(rec.clone()));
        file_actions.push(rec);
    }
    for ent in &report.entries {
        let rec = FileActionRecord {
            kind: FileActionKind::Forensic,
            path: ent.name.clone(),
            detail: format!("[{}] {}", ent.category, ent.detail),
            size_bytes: ent.size_bytes,
            timestamp: None,
        };
        emit(RunnerEvent::FileAction(rec.clone()));
        file_actions.push(rec);
    }

    for line in &log_lines {
        emit(RunnerEvent::LogLine(line.clone()));
    }
    for w in &report.warnings {
        emit(RunnerEvent::LogLine(format!("[WARN] {w}")));
        log_lines.push(format!("[WARN] {w}"));
    }

    emit(RunnerEvent::Progress {
        percent: 100.0,
        current_file: Some(report.path.clone()),
    });

    let summary = RunSummary {
        properties_seen: report.metadata.len() as u64,
        bytes_processed: report.total_bytes,
        log_lines_seen: log_lines.len() as u64,
        ..Default::default()
    };
    emit(RunnerEvent::Summary(summary.clone()));

    let mut hasher = Sha256::new();
    let mut hasher512 = Sha512::new();
    for l in &log_lines {
        hasher.update(l.as_bytes());
        hasher.update(b"\n");
        hasher512.update(l.as_bytes());
        hasher512.update(b"\n");
    }

    Ok(RunResult {
        job_name: job.name.clone(),
        tool: ToolFamily::Forensics,
        operation: AndroidOperation::InspectArtifact,
        source: job.source_path.clone(),
        destination: job.target_path.clone(),
        dry_run: false,
        command_line: command_line.to_string(),
        args: args.to_vec(),
        started_at: started_at.to_string(),
        ended_at: Utc::now().to_rfc3339(),
        duration_secs: timer.elapsed().as_secs_f64(),
        exit_code: 0,
        status_info: decode_exit_code(0),
        cancelled: false,
        summary,
        file_actions,
        forensic_report: Some(report),
        errors: Vec::new(),
        log_lines,
        log_sha256: android2rust_core::format::encode_hex_lower(&hasher.finalize()),
        log_sha512: android2rust_core::format::encode_hex_lower(&hasher512.finalize()),
        case_meta: job.forensic_opts.case_meta.clone(),
    })
}

fn execute_dry_run_simulation(
    job: &AndroidJob,
    args: &[String],
    command_line: &str,
    started_at: &str,
    timer: Instant,
    emit: &mut impl FnMut(RunnerEvent),
) -> Result<RunResult> {
    let findings = validate_job(job);
    let mut log_lines = vec![
        format!("[DRY-RUN] Pre-flight simulation for: {command_line}"),
        "[DRY-RUN] No connected Android device or filesystem state was modified.".to_string(),
    ];
    let mut file_actions = Vec::new();
    let mut errors = Vec::new();
    let mut forensic_report = None;

    for f in &findings {
        let msg = format!("[{:?}] {}: {}", f.severity, f.code, f.message);
        log_lines.push(msg.clone());
        if matches!(f.severity, android2rust_core::ValidationSeverity::Error) {
            errors.push(msg.clone());
        }
    }

    if !job.source_path.trim().is_empty()
        && Path::new(job.source_path.trim()).exists()
        && let Ok(rep) = inspect_artifact(Path::new(job.source_path.trim()), &job.forensic_opts)
    {
        log_lines.push(format!(
            "[DRY-RUN] Local artifact pre-verified: {} ({}, SHA-256 {})",
            rep.path,
            rep.kind.label(),
            rep.sha256
        ));
        file_actions.push(FileActionRecord {
            kind: FileActionKind::Forensic,
            path: rep.path.clone(),
            detail: format!("{} (SHA-256: {})", rep.kind.label(), rep.sha256),
            size_bytes: Some(rep.total_bytes),
            timestamp: None,
        });
        forensic_report = Some(rep);
    }

    for line in &log_lines {
        emit(RunnerEvent::LogLine(line.clone()));
    }
    emit(RunnerEvent::Progress {
        percent: 100.0,
        current_file: None,
    });

    let summary = RunSummary {
        log_lines_seen: log_lines.len() as u64,
        errors_seen: errors.len() as u64,
        ..Default::default()
    };
    emit(RunnerEvent::Summary(summary.clone()));

    let mut hasher = Sha256::new();
    let mut hasher512 = Sha512::new();
    for l in &log_lines {
        hasher.update(l.as_bytes());
        hasher.update(b"\n");
        hasher512.update(l.as_bytes());
        hasher512.update(b"\n");
    }

    let exit_code = if errors.is_empty() { 0 } else { 1 };

    Ok(RunResult {
        job_name: job.name.clone(),
        tool: job.tool,
        operation: job.operation,
        source: job.source_path.clone(),
        destination: job.target_path.clone(),
        dry_run: true,
        command_line: command_line.to_string(),
        args: args.to_vec(),
        started_at: started_at.to_string(),
        ended_at: Utc::now().to_rfc3339(),
        duration_secs: timer.elapsed().as_secs_f64(),
        exit_code,
        status_info: decode_exit_code(exit_code),
        cancelled: false,
        summary,
        file_actions,
        forensic_report,
        errors,
        log_lines,
        log_sha256: android2rust_core::format::encode_hex_lower(&hasher.finalize()),
        log_sha512: android2rust_core::format::encode_hex_lower(&hasher512.finalize()),
        case_meta: job.forensic_opts.case_meta.clone(),
    })
}

fn resolve_binary(job: &AndroidJob, override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    let eff = job.operation.default_tool();
    match eff {
        ToolFamily::Fastboot => find_fastboot_executable().ok_or_else(|| {
            anyhow!("Android Platform-Tools `fastboot` executable was not found on PATH or ANDROID_HOME.")
        }),
        ToolFamily::Adb => find_adb_executable()
            .ok_or_else(|| anyhow!("Android Platform-Tools `adb` executable was not found on PATH or ANDROID_HOME.")),
        ToolFamily::Forensics => Err(anyhow!("Forensic inspection does not invoke an external binary.")),
        ToolFamily::Wpd => Err(anyhow!(
            "WPD/MTP uses native Windows COM and does not invoke an external binary."
        )),
    }
}

fn parse_optional_datetime(raw: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        && let Some(ndt) = d.and_hms_opt(0, 0, 0)
    {
        return Ok(Some(ndt.and_utc()));
    }
    anyhow::bail!("Invalid date/timestamp '{s}'; expected RFC3339 or YYYY-MM-DD")
}

fn execute_wpd_job(
    job: &AndroidJob,
    args: &[String],
    command_line: &str,
    started_at: &str,
    timer: Instant,
    emit: &mut impl FnMut(RunnerEvent),
) -> Result<RunResult> {
    let mut query = MobileFileQuery {
        device_filter: job.wpd_opts.device_filter.clone().filter(|s| !s.trim().is_empty()),
        pattern: (!job.wpd_opts.pattern.trim().is_empty()).then(|| job.wpd_opts.pattern.clone()),
        use_regex: job.wpd_opts.use_regex,
        min_size: job.wpd_opts.min_size,
        max_size: job.wpd_opts.max_size,
        created_after: parse_optional_datetime(job.wpd_opts.created_after.as_deref())?,
        created_before: parse_optional_datetime(job.wpd_opts.created_before.as_deref())?,
        modified_after: parse_optional_datetime(job.wpd_opts.modified_after.as_deref())?,
        modified_before: parse_optional_datetime(job.wpd_opts.modified_before.as_deref())?,
        max_results: job.wpd_opts.max_results,
        ..Default::default()
    };
    if let Some(m) = job
        .wpd_opts
        .mime_or_ext
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if m.contains('/') || m.contains('*') {
            query.content_type = Some(m.to_string());
        } else {
            query.extension = Some(m.to_string());
        }
    }

    let source_dir = job
        .wpd_opts
        .offline_source_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let s = job.source_path.trim();
            if !s.is_empty() && Path::new(s).is_dir() {
                Some(s)
            } else {
                None
            }
        });

    let source: Box<dyn MtpDeviceSource> = if let Some(dir) = source_dir {
        Box::new(DirectoryMtpSource::new(dir))
    } else {
        Box::new(LiveWpdSource::new())
    };

    let search_res = search_devices(source.as_ref(), &query);
    match search_res {
        Err(err @ (WpdError::NoDevices | WpdError::AccessDenied(_) | WpdError::UnsupportedPlatform)) => {
            let code_tok = match &err {
                WpdError::NoDevices => "NO_WPD_DEVICES",
                WpdError::AccessDenied(_) => "WPD_ACCESS_DENIED",
                WpdError::UnsupportedPlatform => "WPD_UNSUPPORTED_PLATFORM",
                _ => "1",
            };
            let err_msg = err.to_string();
            emit(RunnerEvent::Error(err_msg.clone()));
            let mut status_info = decode_status_code(code_tok);
            status_info.exit_code = Some(1);
            let mut h256 = Sha256::new();
            h256.update(err_msg.as_bytes());
            let mut h512 = Sha512::new();
            h512.update(err_msg.as_bytes());
            Ok(RunResult {
                job_name: job.name.clone(),
                tool: ToolFamily::Wpd,
                operation: AndroidOperation::MobileFileSearch,
                source: source_dir.unwrap_or("live://wpd").to_string(),
                destination: job.target_path.clone(),
                dry_run: false,
                command_line: command_line.to_string(),
                args: args.to_vec(),
                started_at: started_at.to_string(),
                ended_at: Utc::now().to_rfc3339(),
                duration_secs: timer.elapsed().as_secs_f64(),
                exit_code: 1,
                status_info,
                cancelled: false,
                summary: RunSummary {
                    errors_seen: 1,
                    log_lines_seen: 1,
                    ..Default::default()
                },
                file_actions: Vec::new(),
                forensic_report: None,
                errors: vec![err_msg.clone()],
                log_lines: vec![err_msg],
                log_sha256: android2rust_core::format::encode_hex_lower(&h256.finalize()),
                log_sha512: android2rust_core::format::encode_hex_lower(&h512.finalize()),
                case_meta: job.forensic_opts.case_meta.clone(),
            })
        }
        Err(err) => Err(anyhow!("{err}")),
        Ok(entries) => {
            let mut log_lines = Vec::with_capacity(entries.len() + 4);
            let mut file_actions = Vec::with_capacity(entries.len());
            let mut total_bytes = 0u64;

            log_lines.push(format!(
                "WPD/MTP File Search matched {} object(s) from {}.",
                entries.len(),
                source_dir.unwrap_or("live WPD/MTP devices")
            ));

            for e in &entries {
                total_bytes = total_bytes.saturating_add(e.size_bytes);
                let rec = FileActionRecord {
                    kind: FileActionKind::Wpd,
                    path: format!("{}/{}{}", e.device_name, e.storage_name, e.full_path),
                    detail: format!("{} ({} bytes, id={})", e.content_type, e.size_bytes, e.object_id),
                    size_bytes: Some(e.size_bytes),
                    timestamp: e.modified_time.map(|t| t.to_rfc3339()),
                };
                emit(RunnerEvent::FileAction(rec.clone()));
                file_actions.push(rec);
                log_lines.push(format!(
                    "[WPD] {} | {} | {} bytes | {}",
                    e.device_name, e.full_path, e.size_bytes, e.content_type
                ));
            }

            let copy_dir = job
                .wpd_opts
                .copy_out_dir
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    let t = job.target_path.trim();
                    if t.is_empty() { None } else { Some(t) }
                });
            let mut files_transferred = 0u64;
            if let Some(out_dir) = copy_dir {
                let copied = copy_out(
                    source.as_ref(),
                    &entries,
                    Path::new(out_dir),
                    &CopyOutOptions::default(),
                )
                .map_err(|e| anyhow!("WPD copy-out failed: {e}"))?;
                files_transferred = copied.len() as u64;
                for c in copied {
                    log_lines.push(format!(
                        "[COPY-OUT] {} -> {} ({} bytes)",
                        c.source_path,
                        c.destination_path.display(),
                        c.bytes_written
                    ));
                }
            }

            for line in &log_lines {
                emit(RunnerEvent::LogLine(line.clone()));
            }
            emit(RunnerEvent::Progress {
                percent: 100.0,
                current_file: None,
            });
            let summary = RunSummary {
                files_transferred,
                bytes_processed: total_bytes,
                log_lines_seen: log_lines.len() as u64,
                ..Default::default()
            };
            emit(RunnerEvent::Summary(summary.clone()));

            let mut h256 = Sha256::new();
            let mut h512 = Sha512::new();
            for l in &log_lines {
                h256.update(l.as_bytes());
                h256.update(b"\n");
                h512.update(l.as_bytes());
                h512.update(b"\n");
            }

            Ok(RunResult {
                job_name: job.name.clone(),
                tool: ToolFamily::Wpd,
                operation: AndroidOperation::MobileFileSearch,
                source: source_dir.unwrap_or("live://wpd").to_string(),
                destination: copy_dir.unwrap_or("").to_string(),
                dry_run: false,
                command_line: command_line.to_string(),
                args: args.to_vec(),
                started_at: started_at.to_string(),
                ended_at: Utc::now().to_rfc3339(),
                duration_secs: timer.elapsed().as_secs_f64(),
                exit_code: 0,
                status_info: decode_exit_code(0),
                cancelled: false,
                summary,
                file_actions,
                forensic_report: None,
                errors: Vec::new(),
                log_lines,
                log_sha256: android2rust_core::format::encode_hex_lower(&h256.finalize()),
                log_sha512: android2rust_core::format::encode_hex_lower(&h512.finalize()),
                case_meta: job.forensic_opts.case_meta.clone(),
            })
        }
    }
}

fn build_process_command(binary: &Path, args: &[String]) -> Command {
    let mut cmd = Command::new(binary);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

fn stream_lines<R: Read>(reader: R, is_err: bool, tx: mpsc::Sender<(bool, String)>) {
    const MAX_STREAM_LINE_BYTES: usize = 1024 * 1024;
    let mut buf_reader = BufReader::new(reader);
    let mut chunk = [0u8; 4096];
    let mut line_buf: Vec<u8> = Vec::with_capacity(512);
    let mut last_was_cr = false;

    loop {
        match buf_reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                for &b in &chunk[..n] {
                    if b == b'\r' {
                        let s = String::from_utf8_lossy(&line_buf).into_owned();
                        line_buf.clear();
                        let _ = tx.send((is_err, s));
                        last_was_cr = true;
                    } else if b == b'\n' {
                        if last_was_cr && line_buf.is_empty() {
                            last_was_cr = false;
                            continue;
                        }
                        last_was_cr = false;
                        let s = String::from_utf8_lossy(&line_buf).into_owned();
                        line_buf.clear();
                        let _ = tx.send((is_err, s));
                    } else {
                        last_was_cr = false;
                        if line_buf.len() < MAX_STREAM_LINE_BYTES {
                            line_buf.push(b);
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    if !line_buf.is_empty() {
        let s = String::from_utf8_lossy(&line_buf).into_owned();
        let _ = tx.send((is_err, s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn executes_offline_forensic_job_and_dry_run_without_adb() {
        let tmp = TempDir::new().unwrap();
        let xml = tmp.path().join("prefs.xml");
        std::fs::write(
            &xml,
            r#"<?xml version="1.0"?><map><string name="user_id">alice</string></map>"#,
        )
        .unwrap();

        let forensic_job = AndroidJob {
            name: "Inspect Prefs".to_string(),
            tool: ToolFamily::Forensics,
            operation: AndroidOperation::InspectArtifact,
            source_path: xml.display().to_string(),
            ..Default::default()
        };
        let res = run_job_blocking(&forensic_job, None, &CancelToken::new()).unwrap();
        assert_eq!(res.exit_code, 0);
        assert!(res.forensic_report.is_some());
        assert!(res.file_actions.iter().any(|r| r.path == "user_id"));

        let dry = AndroidJob {
            name: "Dry Install".to_string(),
            tool: ToolFamily::Adb,
            operation: AndroidOperation::InstallApk,
            source_path: xml.display().to_string(),
            dry_run: true,
            ..Default::default()
        };
        let dry_res = run_job_blocking(&dry, None, &CancelToken::new()).unwrap();
        assert!(dry_res.dry_run);
        assert_eq!(dry_res.exit_code, 0);

        // Missing forensic file via spawn_job_runner yields exit_code 1 (not 127)
        let missing_job = AndroidJob {
            name: "Missing Artifact".to_string(),
            tool: ToolFamily::Forensics,
            operation: AndroidOperation::InspectArtifact,
            source_path: tmp.path().join("nonexistent.apk").display().to_string(),
            ..Default::default()
        };
        let (rx, _cancel) = spawn_job_runner(missing_job, None);
        let mut finished = None;
        for ev in rx {
            if let RunnerEvent::Finished(r) = ev {
                finished = Some(*r);
            }
        }
        let err_res = finished.unwrap();
        assert_eq!(err_res.exit_code, 1);
        assert!(err_res.status_info.short_label.contains("Forensic Inspection Error"));
    }

    #[test]
    fn executes_wpd_mobile_file_search_fixture_and_dry_run() {
        let tmp = TempDir::new().unwrap();
        let fixture = tmp.path().join("fixture");
        let dcim = fixture.join("DCIM");
        let copy_dest = tmp.path().join("copied");
        std::fs::create_dir_all(&dcim).unwrap();
        std::fs::write(dcim.join("IMG_01.jpg"), b"jpgdata").unwrap();
        std::fs::write(dcim.join("readme.txt"), b"txtdata").unwrap();

        let mut dry = AndroidJob {
            name: "Dry WPD Search".to_string(),
            tool: ToolFamily::Wpd,
            operation: AndroidOperation::MobileFileSearch,
            dry_run: true,
            ..Default::default()
        };
        dry.wpd_opts.offline_source_dir = Some(fixture.display().to_string());
        dry.wpd_opts.pattern = "*.jpg".to_string();
        let dry_res = run_job_blocking(&dry, None, &CancelToken::new()).unwrap();
        assert!(dry_res.dry_run);
        assert_eq!(dry_res.exit_code, 0);

        let mut live_fixture = dry.clone();
        live_fixture.dry_run = false;
        live_fixture.wpd_opts.copy_out_dir = Some(copy_dest.display().to_string());
        let res = run_job_blocking(&live_fixture, None, &CancelToken::new()).unwrap();
        assert_eq!(res.exit_code, 0);
        assert_eq!(res.file_actions.len(), 1);
        assert_eq!(res.summary.files_transferred, 1);
        assert!(copy_dest.join("DCIM").join("IMG_01.jpg").is_file());
    }
}
