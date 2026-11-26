#![forbid(unsafe_code)]

use android2rust_core::format::{format_bytes, format_duration};
use android2rust_core::{
    AndroidJob, AndroidOperation, CaseMetadata, ForensicOptions, ProfileStore, RunHistoryEntry, ScheduleSpec,
    ToolFamily, ValidationSeverity, build_batch_script, build_powershell_script, build_schtasks_command,
    build_shell_script, builtin_presets, decode_status_code, find_preset, format_command_line, init_logging,
    parse_command_line, parse_recipe, read_recipe_bounded, serialize_recipe, validate_job,
};
use android2rust_mcp::PolicyMode;
use android2rust_report::{
    ReportFormat, export_wpd_results, parse_log_file_with_options, wpd_entries_to_table_provider, write_report,
    write_timeline,
};
use android2rust_runner::{
    CancelToken, RunResult, RunnerEvent, detect_environment, run_job_blocking, spawn_job_runner,
};
use android2rust_wpd::{
    CopyOutOptions, DirectoryMtpSource, LiveWpdSource, MobileFileQuery, MtpDeviceSource, WpdError, copy_out,
    export_wpd_entries_bytes, search_devices,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Args, Parser, Subcommand};
use guap_export::{ExportFormat, ExportOptions};
use guap_table::{TableProvider, TableQuery};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

fn install_signal_handler(cancel: CancelToken) {
    let _ = ctrlc::set_handler(move || {
        if SHUTDOWN_FLAG.swap(true, Ordering::SeqCst) {
            eprintln!("\n[!] Second Ctrl+C received — terminating.");
            std::process::exit(130);
        } else {
            eprintln!("\n[!] Interrupt received — cancelling active ADB/Fastboot process...");
            cancel.cancel();
        }
    });
}

#[derive(Parser, Debug)]
#[command(
    name = "android2rust",
    author = "Android2Rust Contributors",
    version,
    about = "100% pure-Rust ADB & Fastboot GUI launcher, offline Android forensics workstation, CLI orchestrator, and MCP server",
    long_about = "Build, validate, import (.a2r / CLI), inspect (.apk / .ab / .db / XML), dry-run, execute, schedule, and audit Android Platform-Tools workflows in pure Rust.\n\nInvoke without arguments or run `android2rust gui` to launch the native desktop console (`android2rust-win32` on Windows, `android2rust-iced` on Linux/macOS or via `--iced`)."
)]
pub struct Cli {
    /// Logging verbosity level (error, warn, info, debug, trace)
    #[arg(short, long, global = true, default_value = "warn")]
    pub log_level: String,

    /// Optional log output file path
    #[arg(long, global = true)]
    pub log_file: Option<PathBuf>,

    /// Run WPD/MTP MobileFileSearch directly when no subcommand is specified
    #[arg(long)]
    pub mtp: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List all built-in ADB, Fastboot, and Forensic presets
    Presets {
        #[arg(long)]
        json: bool,
    },
    /// Build a validated command and optional .a2r / .bat / .ps1 / .sh / schtasks exports
    Build(BuildArgs),
    /// Parse a raw adb/fastboot command line or .a2r recipe into structured JSON and diagnostics
    Parse(ParseArgs),
    /// Decode an Android/ADB/Fastboot exit code or status string (e.g. INSTALL_FAILED_*, DEVICE_UNAUTHORIZED)
    Decode {
        code: String,
        #[arg(long)]
        json: bool,
    },
    /// Perform pure-Rust offline forensic inspection on an .apk, .ab backup, SQLite .db, XML, or log dump
    Inspect(InspectArgs),
    /// Run a safe non-destructive Dry-Run pre-flight simulation
    DryRun(ExecArgs),
    /// Execute an ADB, Fastboot, or Forensic job with streaming telemetry and status decoding
    Run(RunArgs),
    /// Manage saved persistent Android2Rust job profiles
    Profile(ProfileArgs),
    /// Generate offline HTML, JSON, or Markdown audit reports from an artifact or log file
    Report(ReportArgs),
    /// Detect host OS, adb/fastboot binaries, versions, and configuration directory
    Env {
        #[arg(long)]
        json: bool,
    },
    /// Start the Model Context Protocol (MCP) JSON-RPC 2.0 stdio server
    Mcp(McpArgs),
    /// Search or enumerate Windows Portable Devices (WPD/MTP) and copy out matched files
    Mtp(MtpArgs),
    /// Search files across WPD/MTP devices or an offline directory fixture (alias for `mtp search`)
    #[command(name = "mobile-search")]
    MobileSearch(MobileSearchArgs),
    /// Launch the desktop GUI (`android2rust-win32` on Windows, `android2rust-iced` on Linux/macOS or with `--iced`)
    Gui(GuiArgs),
}

#[derive(Args, Debug, Default)]
pub struct McpArgs {
    /// Print available MCP tools in JSON Schema format and exit
    #[arg(long)]
    pub tools: bool,

    /// Allow mutating WPD MCP tools (still requires confirm_destructive=true per call)
    #[arg(long)]
    pub allow_mutating: bool,
}

#[derive(Args, Debug)]
pub struct MtpArgs {
    #[command(subcommand)]
    pub action: MtpAction,
}

#[derive(Subcommand, Debug)]
pub enum MtpAction {
    /// Enumerate connected WPD/MTP portable devices and storages
    Devices {
        /// Optional offline synthetic MTP directory fixture path
        #[arg(long, alias = "dir")]
        source_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Search files across connected WPD/MTP devices or a directory fixture
    Search(Box<MobileSearchArgs>),
}

#[derive(Args, Debug, Clone)]
pub struct MobileSearchArgs {
    /// Optional positional filename/path pattern (glob or regex with --regex)
    pub pattern_pos: Option<String>,

    /// Filename/path pattern (glob * / ? or regex with --regex)
    #[arg(long)]
    pub pattern: Option<String>,

    /// Treat pattern as a regular expression
    #[arg(long)]
    pub regex: bool,

    /// Minimum file size in bytes
    #[arg(long)]
    pub min_size: Option<u64>,

    /// Maximum file size in bytes
    #[arg(long)]
    pub max_size: Option<u64>,

    /// Filter created timestamp >= (RFC3339 or YYYY-MM-DD)
    #[arg(long)]
    pub created_after: Option<String>,

    /// Filter created timestamp <= (RFC3339 or YYYY-MM-DD)
    #[arg(long)]
    pub created_before: Option<String>,

    /// Filter modified timestamp >= (RFC3339 or YYYY-MM-DD)
    #[arg(long)]
    pub modified_after: Option<String>,

    /// Filter modified timestamp <= (RFC3339 or YYYY-MM-DD)
    #[arg(long)]
    pub modified_before: Option<String>,

    /// MIME type filter (e.g. image/jpeg or image/*)
    #[arg(long)]
    pub mime: Option<String>,

    /// File extension filter (e.g. jpg or .jpg)
    #[arg(long)]
    pub ext: Option<String>,

    /// Maximum number of matched results to return
    #[arg(long)]
    pub max_results: Option<usize>,

    /// Filter by device ID or friendly name substring
    #[arg(long)]
    pub device: Option<String>,

    /// Filter by storage name substring
    #[arg(long)]
    pub storage: Option<String>,

    /// Filter by MTP folder path prefix (e.g. /DCIM/Camera)
    #[arg(long)]
    pub path_prefix: Option<String>,

    /// Include folder entries in search results
    #[arg(long)]
    pub include_folders: bool,

    /// Offline synthetic MTP directory fixture path (uses LiveWpdSource if omitted)
    #[arg(long, alias = "dir")]
    pub source_dir: Option<PathBuf>,

    /// Force live Windows WPD COM enumeration (default when --source-dir is omitted)
    #[arg(long)]
    pub live: bool,

    /// Path-traversal-safe local destination directory to copy matched files into
    #[arg(long)]
    pub copy_out: Option<PathBuf>,

    /// Flatten copied files into --copy-out root instead of preserving MTP subfolders
    #[arg(long)]
    pub flatten: bool,

    /// Output/export format: table, csv, tsv, json, jsonl, html, html-vertical, markdown
    #[arg(long, default_value = "table")]
    pub format: String,

    /// Optional file path to write exported results + SHA-256/512 Merkle custody manifest
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Emit JSON output to stdout
    #[arg(long)]
    pub json: bool,
}

impl Default for MobileSearchArgs {
    fn default() -> Self {
        Self {
            pattern_pos: None,
            pattern: None,
            regex: false,
            min_size: None,
            max_size: None,
            created_after: None,
            created_before: None,
            modified_after: None,
            modified_before: None,
            mime: None,
            ext: None,
            max_results: None,
            device: None,
            storage: None,
            path_prefix: None,
            include_folders: false,
            source_dir: None,
            live: false,
            copy_out: None,
            flatten: false,
            format: "table".to_string(),
            output: None,
            json: false,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct JobSourceArgs {
    #[arg(short, long)]
    pub source: Option<String>,

    #[arg(short, long)]
    pub target: Option<String>,

    #[arg(long)]
    pub serial: Option<String>,

    #[arg(long)]
    pub op: Option<String>,

    #[arg(long)]
    pub preset: Option<String>,

    #[arg(long)]
    pub profile: Option<String>,

    #[arg(long)]
    pub recipe: Option<PathBuf>,

    #[arg(long)]
    pub slot: Option<String>,

    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct BuildArgs {
    #[command(flatten)]
    pub job_args: JobSourceArgs,

    #[arg(long)]
    pub export_recipe: Option<PathBuf>,

    #[arg(long)]
    pub export_bat: Option<PathBuf>,

    #[arg(long)]
    pub export_ps1: Option<PathBuf>,

    #[arg(long)]
    pub export_sh: Option<PathBuf>,

    #[arg(long)]
    pub export_schtasks: bool,

    #[arg(long, default_value = "Android2Rust_Job")]
    pub task_name: String,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ParseArgs {
    /// Raw adb/fastboot command string, or path to an .a2r recipe when --recipe is passed
    pub input: String,

    #[arg(long)]
    pub recipe: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ProvenanceArgs {
    /// Case identifier for chain-of-custody report headers
    #[arg(long)]
    pub case_id: Option<String>,

    /// Evidence / exhibit identifier for chain-of-custody report headers
    #[arg(long)]
    pub evidence_id: Option<String>,

    /// Examiner name for chain-of-custody report headers
    #[arg(long)]
    pub examiner: Option<String>,
}

fn resolve_ab_password(flag: Option<&str>) -> Option<String> {
    flag.map(str::to_string)
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("ANDROID2RUST_AB_PASSWORD").ok().filter(|s| !s.is_empty()))
}

fn build_forensic_opts(prov: &ProvenanceArgs, password: Option<&str>) -> ForensicOptions {
    ForensicOptions {
        case_meta: CaseMetadata {
            case_id: prov.case_id.clone(),
            evidence_id: prov.evidence_id.clone(),
            examiner: prov.examiner.clone(),
        },
        ab_password: resolve_ab_password(password),
        ..Default::default()
    }
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Local path to .apk, .ab, SQLite .db, ABX, XML, bugreport .zip, directory, or log dump
    pub path: PathBuf,

    #[arg(long)]
    pub report: Option<PathBuf>,

    #[arg(long, default_value = "html")]
    pub format: String,

    /// Optional output path for chronological CSV or JSONL timeline export (.csv or .jsonl)
    #[arg(long)]
    pub timeline: Option<PathBuf>,

    /// Optional passphrase to lawfully decrypt encrypted .ab backups (or set ANDROID2RUST_AB_PASSWORD)
    #[arg(long)]
    pub password: Option<String>,

    #[command(flatten)]
    pub provenance: ProvenanceArgs,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ExecArgs {
    #[command(flatten)]
    pub job_args: JobSourceArgs,

    #[arg(long)]
    pub report: Option<PathBuf>,

    #[arg(long, default_value = "html")]
    pub report_format: String,

    /// Optional output path for chronological CSV or JSONL timeline export (.csv or .jsonl)
    #[arg(long)]
    pub timeline: Option<PathBuf>,

    /// Optional passphrase to lawfully decrypt encrypted .ab backups (or set ANDROID2RUST_AB_PASSWORD)
    #[arg(long)]
    pub password: Option<String>,

    #[command(flatten)]
    pub provenance: ProvenanceArgs,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub exec: ExecArgs,

    /// Confirm destructive ADB/Fastboot operations (flash, erase, format, unlock, uninstall, restore)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub action: ProfileAction,
}

#[derive(Subcommand, Debug)]
pub enum ProfileAction {
    List {
        #[arg(long)]
        json: bool,
    },
    Show {
        name: String,
        #[arg(long)]
        json: bool,
    },
    Save {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[command(flatten)]
        job_args: JobSourceArgs,
    },
    Delete {
        name: String,
    },
    ImportRecipe {
        name: String,
        recipe_path: PathBuf,
        #[arg(long, default_value = "")]
        description: String,
    },
    ExportRecipe {
        name: String,
        out_path: PathBuf,
    },
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    #[arg(long)]
    pub log_file: PathBuf,

    #[arg(long)]
    pub output: PathBuf,

    #[arg(long, default_value = "html")]
    pub format: String,

    /// Optional output path for chronological CSV or JSONL timeline export (.csv or .jsonl)
    #[arg(long)]
    pub timeline: Option<PathBuf>,

    /// Optional passphrase to lawfully decrypt encrypted .ab backups (or set ANDROID2RUST_AB_PASSWORD)
    #[arg(long)]
    pub password: Option<String>,

    #[command(flatten)]
    pub provenance: ProvenanceArgs,
}

#[derive(Args, Debug, Default)]
pub struct GuiArgs {
    /// Launch the cross-platform Iced GUI (`android2rust-iced`) on Windows instead of the WinSafe Win32 GUI
    #[arg(long)]
    pub iced: bool,

    #[arg(long)]
    pub source: Option<String>,

    #[arg(long)]
    pub target: Option<String>,

    #[arg(long)]
    pub serial: Option<String>,

    #[arg(long)]
    pub recipe: Option<PathBuf>,

    #[arg(long)]
    pub profile: Option<String>,
}

fn merge_provenance_and_password(job: &mut AndroidJob, prov: &ProvenanceArgs, password: Option<&str>) {
    if let Some(cid) = &prov.case_id {
        job.forensic_opts.case_meta.case_id = Some(cid.clone());
    }
    if let Some(eid) = &prov.evidence_id {
        job.forensic_opts.case_meta.evidence_id = Some(eid.clone());
    }
    if let Some(ex) = &prov.examiner {
        job.forensic_opts.case_meta.examiner = Some(ex.clone());
    }
    if let Some(pw) = resolve_ab_password(password) {
        job.forensic_opts.ab_password = Some(pw);
    }
}

fn assemble_job(args: &JobSourceArgs) -> Result<AndroidJob> {
    let mut job = if let Some(recipe_path) = &args.recipe {
        let bytes = read_recipe_bounded(recipe_path)?;
        let (parsed, warnings) = parse_recipe(&bytes)?;
        for w in warnings {
            eprintln!("[warn] .a2r: {w}");
        }
        parsed
    } else if let Some(prof_name) = &args.profile {
        let store = ProfileStore::default_store();
        let prof = store
            .find_profile(prof_name)?
            .ok_or_else(|| anyhow::anyhow!("Saved profile not found: {prof_name}"))?;
        prof.job
    } else if let Some(preset_name) = &args.preset {
        find_preset(preset_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown built-in preset: {preset_name}"))?
            .job
    } else {
        AndroidJob::default()
    };

    if let Some(op_slug) = &args.op {
        let op =
            AndroidOperation::from_slug(op_slug).ok_or_else(|| anyhow::anyhow!("Unknown operation slug: {op_slug}"))?;
        job.operation = op;
        job.tool = op.default_tool();
    }
    if let Some(s) = &args.source {
        job.source_path = s.clone();
    }
    if let Some(t) = &args.target {
        job.target_path = t.clone();
        if job.tool == ToolFamily::Fastboot {
            job.fastboot_opts.partition = t.clone();
        }
    }
    if let Some(serial) = &args.serial {
        job.serial = serial.clone();
    }
    if let Some(slot) = &args.slot {
        job.fastboot_opts.slot = Some(slot.clone());
    }
    if args.dry_run {
        job = job.with_dry_run();
    }
    Ok(job)
}

fn print_validation_findings(job: &AndroidJob) -> bool {
    let findings = validate_job(job);
    let mut has_error = false;
    for f in &findings {
        let tag = match f.severity {
            ValidationSeverity::Error => {
                has_error = true;
                "ERROR"
            }
            ValidationSeverity::Warning => "WARN",
            ValidationSeverity::Info => "INFO",
        };
        eprintln!("[{tag}] {}: {}", f.code, f.message);
        if let Some(sug) = &f.suggestion {
            eprintln!("       Suggestion: {sug}");
        }
    }
    has_error
}

fn execute_and_report(job: AndroidJob, exec: &ExecArgs) -> Result<i32> {
    if print_validation_findings(&job) {
        bail!("Validation errors prevented execution.");
    }

    let (rx, cancel) = spawn_job_runner(job.clone(), None);
    install_signal_handler(cancel);

    let mut final_result: Option<RunResult> = None;
    for ev in rx {
        match ev {
            RunnerEvent::Started { command_line } => {
                if !exec.json {
                    println!("> {command_line}");
                }
            }
            RunnerEvent::LogLine(line) => {
                if !exec.json {
                    println!("{line}");
                }
            }
            RunnerEvent::FileAction(rec) => {
                if !exec.json {
                    println!("[{}] {} -> {}", rec.kind.label(), rec.path, rec.detail);
                }
            }
            RunnerEvent::Error(err) => {
                if !exec.json {
                    eprintln!("[error] {err}");
                }
            }
            RunnerEvent::Finished(res) => {
                final_result = Some(*res);
            }
            RunnerEvent::Progress { .. } | RunnerEvent::Summary(_) => {}
        }
    }

    let res = final_result.ok_or_else(|| anyhow::anyhow!("Runner exited without producing a result"))?;

    let store = ProfileStore::default_store();
    let _ = store.append_history(RunHistoryEntry {
        id: format!("run-{}", Utc::now().timestamp_millis()),
        timestamp: res.ended_at.clone(),
        job_name: res.job_name.clone(),
        source: res.source.clone(),
        destination: res.destination.clone(),
        dry_run: res.dry_run,
        command_line: res.command_line.clone(),
        exit_code: res.exit_code,
        exit_label: res.status_info.short_label.clone(),
        is_success: res.status_info.is_success,
        duration_secs: res.duration_secs,
        records_count: res.file_actions.len() as u64,
        error_count: res.errors.len() as u64,
        bytes_processed: res.summary.bytes_processed,
        summary_text: res.status_info.summary.clone(),
    });

    if let Some(report_out) = &exec.report {
        let fmt = ReportFormat::parse(&exec.report_format)?;
        let written = write_report(&res, fmt, report_out)?;
        if !exec.json {
            for p in written {
                println!("Report written: {}", p.display());
            }
        }
    }
    if let Some(tl_out) = &exec.timeline {
        let tl_path = write_timeline(&res, tl_out)?;
        if !exec.json {
            println!("Timeline written: {}", tl_path.display());
        }
    }

    if exec.json {
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        println!();
        println!(
            "=== Android2Rust Finished in {} ===",
            format_duration(res.duration_secs)
        );
        println!("Status    : {} ({})", res.exit_code, res.status_info.short_label);
        println!("Summary   : {}", res.status_info.summary);
        println!(
            "Records   : {}, Devices {}, Packages {}, Props {}, Bytes {}",
            res.file_actions.len(),
            res.summary.devices_seen,
            res.summary.packages_seen,
            res.summary.properties_seen,
            format_bytes(res.summary.bytes_processed),
        );
        println!("SHA-256   : {}", res.log_sha256);
        if !res.log_sha512.is_empty() {
            println!("SHA-512   : {}", res.log_sha512);
        }
    }

    if res.status_info.is_success {
        Ok(0)
    } else {
        Ok(res.exit_code.max(1))
    }
}

fn launch_gui(args: &GuiArgs) -> Result<()> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));

    let resolve_candidate = |bin_name: &str| -> PathBuf {
        exe_dir
            .as_ref()
            .map(|d| d.join(bin_name))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from(bin_name))
    };

    let candidate = if cfg!(windows) && !args.iced {
        let win32_bin = resolve_candidate("android2rust-win32.exe");
        let iced_bin = resolve_candidate("android2rust-iced.exe");
        if win32_bin.is_file() || !iced_bin.is_file() {
            win32_bin
        } else {
            iced_bin
        }
    } else if cfg!(windows) {
        resolve_candidate("android2rust-iced.exe")
    } else {
        resolve_candidate("android2rust-iced")
    };

    let mut cmd = std::process::Command::new(&candidate);
    if let Some(s) = &args.source {
        cmd.arg("--source").arg(s);
    }
    if let Some(t) = &args.target {
        cmd.arg("--target").arg(t);
    }
    if let Some(ser) = &args.serial {
        cmd.arg("--serial").arg(ser);
    }
    if let Some(r) = &args.recipe {
        cmd.arg("--recipe").arg(r);
    }
    if let Some(prof) = &args.profile {
        cmd.arg("--profile").arg(prof);
    }
    cmd.spawn()
        .with_context(|| format!("Failed to launch GUI executable {}", candidate.display()))?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let _ = init_logging(&cli.log_level, cli.log_file.as_deref());

    let code = match run_cli(cli) {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("Error: {err:#}");
            1
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn run_cli(cli: Cli) -> Result<i32> {
    let Some(command) = cli.command else {
        if cli.mtp {
            return execute_mtp_search(&MobileSearchArgs::default());
        }
        launch_gui(&GuiArgs::default())?;
        return Ok(0);
    };

    match command {
        Commands::Presets { json: as_json } => {
            let presets = builtin_presets();
            if as_json {
                println!("{}", serde_json::to_string_pretty(&presets)?);
            } else {
                for p in presets {
                    let tag = if p.destructive { " [DESTRUCTIVE]" } else { "" };
                    println!("{:<26} | {}{}", p.id, p.name, tag);
                    println!("   {}", p.summary);
                }
            }
            Ok(0)
        }
        Commands::Build(b) => {
            let job = assemble_job(&b.job_args)?;
            let findings = validate_job(&job);
            let cmd_line = format_command_line(&job);

            if let Some(p) = &b.export_recipe {
                std::fs::write(p, serialize_recipe(&job))?;
            }
            if let Some(p) = &b.export_bat {
                std::fs::write(p, build_batch_script(&job))?;
            }
            if let Some(p) = &b.export_ps1 {
                std::fs::write(p, build_powershell_script(&job))?;
            }
            if let Some(p) = &b.export_sh {
                std::fs::write(p, build_shell_script(&job))?;
            }

            let schtasks = if b.export_schtasks {
                Some(build_schtasks_command(
                    &b.task_name,
                    &cmd_line,
                    &ScheduleSpec::default(),
                ))
            } else {
                None
            };

            if b.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command_line": cmd_line,
                        "findings": findings,
                        "schtasks": schtasks,
                        "job": job,
                    }))?
                );
            } else {
                println!("{cmd_line}");
                if let Some(st) = schtasks {
                    println!("\nTask Scheduler Command:\n{st}");
                }
                let _ = print_validation_findings(&job);
            }
            Ok(0)
        }
        Commands::Parse(p) => {
            let (job, warnings) = if p.recipe {
                let bytes = read_recipe_bounded(Path::new(&p.input))?;
                parse_recipe(&bytes)?
            } else {
                let parsed = parse_command_line(&p.input);
                (parsed.job, parsed.unrecognized_tokens)
            };
            let findings = validate_job(&job);
            if p.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "command_line": format_command_line(&job),
                        "warnings": warnings,
                        "findings": findings,
                        "job": job,
                    }))?
                );
            } else {
                println!("Normalized Command:\n  {}", format_command_line(&job));
                for w in warnings {
                    eprintln!("[parse warn] {w}");
                }
                let _ = print_validation_findings(&job);
            }
            Ok(0)
        }
        Commands::Decode { code, json: as_json } => {
            let info = decode_status_code(&code);
            if as_json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("Status   : {}", info.short_label);
                println!("Severity : {}", info.severity.label());
                println!("Success  : {}", info.is_success);
                println!("Summary  : {}", info.summary);
                for d in &info.details {
                    println!("  - {d}");
                }
            }
            Ok(0)
        }
        Commands::Inspect(ins) => {
            let job = AndroidJob {
                name: ins
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("Artifact Inspection")
                    .to_string(),
                tool: ToolFamily::Forensics,
                operation: AndroidOperation::InspectArtifact,
                source_path: ins.path.display().to_string(),
                forensic_opts: build_forensic_opts(&ins.provenance, ins.password.as_deref()),
                ..Default::default()
            };
            let run_res = run_job_blocking(&job, None, &CancelToken::new())?;
            let rep = run_res
                .forensic_report
                .as_ref()
                .context("Forensic job completed without a forensic report")?;
            if let Some(out) = &ins.report {
                let fmt = ReportFormat::parse(&ins.format)?;
                let written = write_report(&run_res, fmt, out)?;
                if !ins.json {
                    for p in written {
                        println!("Audit report written: {}", p.display());
                    }
                }
            }
            if let Some(tl_out) = &ins.timeline {
                let tl_path = write_timeline(&run_res, tl_out)?;
                if !ins.json {
                    println!("Timeline written: {}", tl_path.display());
                }
            }
            if ins.json {
                println!("{}", serde_json::to_string_pretty(rep)?);
            } else {
                println!("Artifact : {}", rep.path);
                println!("Format   : {}", rep.kind.label());
                println!("Size     : {}", format_bytes(rep.total_bytes));
                println!("SHA-256  : {}", rep.sha256);
                if !rep.sha512.is_empty() {
                    println!("SHA-512  : {}", rep.sha512);
                }
                if !rep.timeline.is_empty() {
                    println!("Timeline : {} events", rep.timeline.len());
                }
                for (k, v) in &rep.metadata {
                    println!("  {k:<22}: {v}");
                }
                if !rep.permissions_or_tables.is_empty() {
                    println!("Permissions / Tables ({}):", rep.permissions_or_tables.len());
                    for p in &rep.permissions_or_tables {
                        println!("  - {p}");
                    }
                }
                if !rep.warnings.is_empty() {
                    println!("Warnings ({}):", rep.warnings.len());
                    for w in &rep.warnings {
                        println!("  [WARN] {w}");
                    }
                }
                if !rep.entries.is_empty() {
                    println!("Entries ({} shown):", rep.entries.len().min(25));
                    for e in rep.entries.iter().take(25) {
                        println!("  [{}] {} — {}", e.category, e.name, e.detail);
                    }
                }
            }
            Ok(0)
        }
        Commands::DryRun(exec) => {
            let mut job = assemble_job(&exec.job_args)?.with_dry_run();
            merge_provenance_and_password(&mut job, &exec.provenance, exec.password.as_deref());
            execute_and_report(job, &exec)
        }
        Commands::Run(run) => {
            let mut job = assemble_job(&run.exec.job_args)?;
            merge_provenance_and_password(&mut job, &run.exec.provenance, run.exec.password.as_deref());
            if job.is_destructive() && !run.yes {
                let reasons = job.destructive_reasons().join(", ");
                bail!(
                    "Refusing destructive Android execution ({reasons}) without --yes. Run `android2rust dry-run` first or pass --yes."
                );
            }
            execute_and_report(job, &run.exec)
        }
        Commands::Profile(prof) => {
            let store = ProfileStore::default_store();
            match prof.action {
                ProfileAction::List { json: as_json } => {
                    let list = store.load_profiles()?;
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&list)?);
                    } else if list.is_empty() {
                        println!("No saved profiles in {}", store.profiles_path().display());
                    } else {
                        for p in list {
                            println!(
                                "{} ({}) -> {} | {}",
                                p.name,
                                p.id,
                                p.job.operation.label(),
                                format_command_line(&p.job)
                            );
                        }
                    }
                }
                ProfileAction::Show { name, json: as_json } => {
                    let p = store
                        .find_profile(&name)?
                        .ok_or_else(|| anyhow::anyhow!("Profile not found: {name}"))?;
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&p)?);
                    } else {
                        println!("Name       : {}", p.name);
                        println!("Description: {}", p.description);
                        println!("Command    : {}", format_command_line(&p.job));
                    }
                }
                ProfileAction::Save {
                    name,
                    description,
                    job_args,
                } => {
                    let job = assemble_job(&job_args)?;
                    let list = store.upsert_profile(&name, &description, job)?;
                    println!("Saved profile '{name}' ({} total profiles).", list.len());
                }
                ProfileAction::Delete { name } => {
                    let (removed, _) = store.delete_profile(&name)?;
                    if removed {
                        println!("Deleted profile '{name}'.");
                    } else {
                        bail!("Profile not found: {name}");
                    }
                }
                ProfileAction::ImportRecipe {
                    name,
                    recipe_path,
                    description,
                } => {
                    let bytes = read_recipe_bounded(&recipe_path)?;
                    let (job, _) = parse_recipe(&bytes)?;
                    store.upsert_profile(&name, &description, job)?;
                    println!("Imported {} into profile '{name}'.", recipe_path.display());
                }
                ProfileAction::ExportRecipe { name, out_path } => {
                    let p = store
                        .find_profile(&name)?
                        .ok_or_else(|| anyhow::anyhow!("Profile not found: {name}"))?;
                    std::fs::write(&out_path, serialize_recipe(&p.job))?;
                    println!("Exported profile '{name}' to {}", out_path.display());
                }
            }
            Ok(0)
        }
        Commands::Report(rep) => {
            let fmt = ReportFormat::parse(&rep.format)?;
            let opts = build_forensic_opts(&rep.provenance, rep.password.as_deref());
            let res = parse_log_file_with_options(&rep.log_file, opts)?;
            let written = write_report(&res, fmt, &rep.output)?;
            for p in written {
                println!("Generated report: {}", p.display());
            }
            if let Some(tl_out) = &rep.timeline {
                let tl_path = write_timeline(&res, tl_out)?;
                println!("Timeline written: {}", tl_path.display());
            }
            Ok(0)
        }
        Commands::Env { json: as_json } => {
            let env = detect_environment();
            if as_json {
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("OS                 : {}", env.os);
                println!("ADB Available      : {}", env.adb_available);
                println!(
                    "ADB Path           : {}",
                    env.adb_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<not found>".to_string())
                );
                if let Some(v) = &env.adb_version {
                    println!("ADB Version        : {v}");
                }
                println!("Fastboot Available : {}", env.fastboot_available);
                println!(
                    "Fastboot Path      : {}",
                    env.fastboot_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<not found>".to_string())
                );
                if let Some(v) = &env.fastboot_version {
                    println!("Fastboot Version   : {v}");
                }
                println!("Config Directory   : {}", env.config_dir.display());
            }
            Ok(0)
        }
        Commands::Mcp(args) => {
            if args.tools {
                let manifest = android2rust_mcp::get_tools_manifest();
                println!("{}", serde_json::to_string_pretty(&manifest)?);
                return Ok(0);
            }
            let policy = if args.allow_mutating {
                PolicyMode::AllowMutating
            } else {
                PolicyMode::ReadOnlyOnly
            };
            android2rust_mcp::run_stdio_server_with_policy(policy).map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(0)
        }
        Commands::Mtp(mtp) => match mtp.action {
            MtpAction::Devices {
                source_dir,
                json: as_json,
            } => execute_mtp_devices(source_dir.as_deref(), as_json),
            MtpAction::Search(args) => execute_mtp_search(&args),
        },
        Commands::MobileSearch(args) => execute_mtp_search(&args),
        Commands::Gui(g) => {
            launch_gui(&g)?;
            Ok(0)
        }
    }
}

fn parse_cli_datetime(raw: Option<&str>) -> Result<Option<DateTime<Utc>>> {
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
    bail!("Invalid timestamp '{s}'; expected RFC3339 or YYYY-MM-DD")
}

fn select_cli_wpd_source(source_dir: Option<&Path>, force_live: bool) -> Box<dyn MtpDeviceSource> {
    if !force_live && let Some(dir) = source_dir {
        Box::new(DirectoryMtpSource::new(dir))
    } else {
        Box::new(LiveWpdSource::new())
    }
}

fn print_wpd_unavailable(err: &WpdError, as_json: bool) -> Result<i32> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "unavailable",
                "error": err.to_string(),
                "devices": [],
                "results": []
            }))?
        );
    } else {
        eprintln!("WPD/MTP unavailable: {err}");
    }
    Ok(1)
}

fn execute_mtp_devices(source_dir: Option<&Path>, as_json: bool) -> Result<i32> {
    let src = select_cli_wpd_source(source_dir, false);
    match src.list_devices() {
        Ok(devices) => {
            if devices.is_empty() {
                return print_wpd_unavailable(&WpdError::NoDevices, as_json);
            }
            if as_json {
                println!("{}", serde_json::to_string_pretty(&devices)?);
            } else {
                for d in &devices {
                    println!("{} | {} | {}", d.id, d.friendly_name, d.manufacturer);
                    for s in &d.storages {
                        println!("  - Storage: {} (id={}, fs={})", s.name, s.object_id, s.file_system);
                    }
                }
            }
            Ok(0)
        }
        Err(err @ (WpdError::NoDevices | WpdError::UnsupportedPlatform | WpdError::AccessDenied(_))) => {
            print_wpd_unavailable(&err, as_json)
        }
        Err(err) => Err(anyhow::anyhow!("{err}")),
    }
}

fn execute_mtp_search(args: &MobileSearchArgs) -> Result<i32> {
    let effective_pattern = args
        .pattern
        .as_deref()
        .or(args.pattern_pos.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let query = MobileFileQuery {
        device_filter: args.device.clone(),
        storage_filter: args.storage.clone(),
        path_prefix: args.path_prefix.clone(),
        pattern: effective_pattern,
        use_regex: args.regex,
        min_size: args.min_size,
        max_size: args.max_size,
        created_after: parse_cli_datetime(args.created_after.as_deref())?,
        created_before: parse_cli_datetime(args.created_before.as_deref())?,
        modified_after: parse_cli_datetime(args.modified_after.as_deref())?,
        modified_before: parse_cli_datetime(args.modified_before.as_deref())?,
        content_type: args.mime.clone(),
        extension: args.ext.clone(),
        include_folders: args.include_folders,
        max_results: args.max_results,
    };
    query.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

    let source = select_cli_wpd_source(args.source_dir.as_deref(), args.live);
    let entries = match search_devices(source.as_ref(), &query) {
        Ok(list) => list,
        Err(err @ (WpdError::NoDevices | WpdError::UnsupportedPlatform | WpdError::AccessDenied(_))) => {
            return print_wpd_unavailable(&err, args.json);
        }
        Err(err) => return Err(anyhow::anyhow!("{err}")),
    };

    let copied = if let Some(dest) = &args.copy_out {
        let opts = CopyOutOptions {
            preserve_tree: !args.flatten,
            overwrite: false,
            max_copy_bytes: None,
        };
        Some(copy_out(source.as_ref(), &entries, dest, &opts).map_err(|e| anyhow::anyhow!("{e}"))?)
    } else {
        None
    };

    let custody = if let Some(out_path) = &args.output {
        let fmt = if args.format.trim().is_empty() || args.format.trim().eq_ignore_ascii_case("table") {
            ExportFormat::Csv
        } else {
            ExportFormat::parse(&args.format).map_err(|e| anyhow::anyhow!("{e}"))?
        };
        Some(export_wpd_results(&entries, fmt, out_path)?)
    } else {
        None
    };

    if args.json {
        let provider = wpd_entries_to_table_provider(&entries);
        let table = provider.query(&TableQuery::default())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "matched_count": entries.len(),
                "entries": entries,
                "table_total_rows": table.total_rows,
                "copied": copied,
                "custody_manifest": custody,
            }))?
        );
    } else if !args.format.trim().is_empty()
        && !args.format.trim().eq_ignore_ascii_case("table")
        && args.output.is_none()
    {
        let fmt = ExportFormat::parse(&args.format).map_err(|e| anyhow::anyhow!("{e}"))?;
        let bytes =
            export_wpd_entries_bytes(&entries, fmt, &ExportOptions::default()).map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("{}", String::from_utf8_lossy(&bytes));
    } else {
        println!("Matched {} WPD/MTP object(s):", entries.len());
        for e in &entries {
            println!(
                "  [{}] {} | {} | {} | {} bytes | {}",
                e.device_name, e.storage_name, e.full_path, e.object_id, e.size_bytes, e.content_type
            );
        }
        if let Some(records) = &copied {
            println!("Copied out {} file(s):", records.len());
            for r in records {
                println!("  -> {} ({} bytes)", r.destination_path.display(), r.bytes_written);
            }
        }
        if let Some(m) = &custody {
            println!("Exported {} artifact(s)", m.artifact_count);
            println!("Merkle SHA-256 : {}", m.merkle_root_sha256);
            println!("Merkle SHA-512 : {}", m.merkle_root_sha512);
        }
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_gui_iced_and_build_flags() {
        let cli = Cli::try_parse_from([
            "android2rust",
            "gui",
            "--iced",
            "--source",
            r"C:\Apps\app.apk",
            "--serial",
            "R58M123",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Gui(g)) => {
                assert!(g.iced);
                assert_eq!(g.source.as_deref(), Some(r"C:\Apps\app.apk"));
                assert_eq!(g.serial.as_deref(), Some("R58M123"));
            }
            other => panic!("Unexpected command: {other:?}"),
        }

        let build_cli = Cli::try_parse_from([
            "android2rust",
            "build",
            "--preset",
            "fastboot-flash-image",
            "--slot",
            "a",
            "--source",
            "boot.img",
            "--target",
            "boot",
        ])
        .unwrap();
        match build_cli.command {
            Some(Commands::Build(b)) => {
                let job = assemble_job(&b.job_args).unwrap();
                assert_eq!(format_command_line(&job), "fastboot --slot a flash boot boot.img");
            }
            other => panic!("Unexpected command: {other:?}"),
        }
    }

    #[test]
    fn run_command_refuses_destructive_flash_without_yes() {
        let cli = Cli::try_parse_from([
            "android2rust",
            "run",
            "--preset",
            "fastboot-flash-image",
            "--source",
            "boot.img",
            "--target",
            "boot",
        ])
        .unwrap();
        let err = run_cli(cli).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--yes"), "expected --yes refusal prompt, got: {msg}");
    }

    #[test]
    fn inspect_and_report_parse_provenance_password_and_timeline_flags() {
        let cli = Cli::try_parse_from([
            "android2rust",
            "inspect",
            "backup.ab",
            "--password",
            "pass123",
            "--case-id",
            "IR-01",
            "--evidence-id",
            "EV-02",
            "--examiner",
            "Examiner",
            "--timeline",
            "out.jsonl",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Inspect(ins)) => {
                assert_eq!(ins.password.as_deref(), Some("pass123"));
                assert_eq!(ins.provenance.case_id.as_deref(), Some("IR-01"));
                assert_eq!(ins.provenance.evidence_id.as_deref(), Some("EV-02"));
                assert_eq!(ins.provenance.examiner.as_deref(), Some("Examiner"));
                assert_eq!(ins.timeline.as_deref(), Some(Path::new("out.jsonl")));
            }
            other => panic!("Unexpected command: {other:?}"),
        }

        let runtime_pw = format!("cli-pw-{}", std::process::id());
        let dry_cli = Cli::try_parse_from([
            "android2rust",
            "dry-run",
            "--op",
            "inspect",
            "--source",
            "backup.ab",
            "--password",
            &runtime_pw,
            "--examiner",
            "Override",
        ])
        .unwrap();
        match dry_cli.command {
            Some(Commands::DryRun(exec)) => {
                let mut job = assemble_job(&exec.job_args).unwrap();
                job.forensic_opts.case_meta.case_id = Some("RECIPE-CASE".to_string());
                merge_provenance_and_password(&mut job, &exec.provenance, exec.password.as_deref());
                assert_eq!(job.forensic_opts.case_meta.case_id.as_deref(), Some("RECIPE-CASE"));
                assert_eq!(job.forensic_opts.case_meta.examiner.as_deref(), Some("Override"));
                assert_eq!(job.forensic_opts.ab_password.as_deref(), Some(runtime_pw.as_str()));
            }
            other => panic!("Unexpected command: {other:?}"),
        }
    }

    #[test]
    fn cli_parses_mtp_and_mobile_search_and_runs_offline_fixture() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dcim = tmp.path().join("DCIM");
        let out_csv = tmp.path().join("results.csv");
        let copy_dir = tmp.path().join("copied");
        std::fs::create_dir_all(&dcim).unwrap();
        std::fs::write(dcim.join("photo.jpg"), b"jpeg-bytes").unwrap();
        std::fs::write(dcim.join("doc.txt"), b"text-bytes").unwrap();

        let cli = Cli::try_parse_from([
            "android2rust",
            "mtp",
            "search",
            "--source-dir",
            &tmp.path().display().to_string(),
            "--pattern",
            "*.jpg",
            "--copy-out",
            &copy_dir.display().to_string(),
            "--format",
            "csv",
            "--output",
            &out_csv.display().to_string(),
        ])
        .unwrap();
        assert_eq!(run_cli(cli).unwrap(), 0);
        assert!(copy_dir.join("DCIM").join("photo.jpg").is_file());
        assert!(!copy_dir.join("DCIM").join("doc.txt").exists());
        assert!(out_csv.is_file());

        let alias_cli = Cli::try_parse_from([
            "android2rust",
            "mobile-search",
            "--source-dir",
            &tmp.path().display().to_string(),
            "--ext",
            "txt",
            "--json",
        ])
        .unwrap();
        assert_eq!(run_cli(alias_cli).unwrap(), 0);

        let mtp_flag_cli = Cli::try_parse_from(["android2rust", "--mtp"]).unwrap();
        assert!(mtp_flag_cli.mtp);

        let mcp_cli = Cli::try_parse_from(["android2rust", "mcp", "--allow-mutating"]).unwrap();
        match mcp_cli.command {
            Some(Commands::Mcp(m)) => assert!(m.allow_mutating),
            other => panic!("Unexpected command: {other:?}"),
        }
    }

    #[test]
    fn mobile_search_args_default_format_succeeds_on_source_dir() {
        assert_eq!(MobileSearchArgs::default().format, "table");

        let tmp = tempfile::TempDir::new().unwrap();
        let dcim = tmp.path().join("DCIM").join("Camera");
        std::fs::create_dir_all(&dcim).unwrap();
        std::fs::write(dcim.join("IMG_0042.jpg"), b"jpeg-bytes").unwrap();

        let default_args = MobileSearchArgs {
            source_dir: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(execute_mtp_search(&default_args).unwrap(), 0);

        let empty_format_args = MobileSearchArgs {
            source_dir: Some(tmp.path().to_path_buf()),
            format: String::new(),
            ..Default::default()
        };
        assert_eq!(execute_mtp_search(&empty_format_args).unwrap(), 0);

        let regex_cli = Cli::try_parse_from([
            "android2rust",
            "mobile-search",
            "--source-dir",
            &tmp.path().display().to_string(),
            "--regex",
            "--pattern",
            r"^IMG_\d{4}\.jpg$",
        ])
        .unwrap();
        assert_eq!(run_cli(regex_cli).unwrap(), 0);
    }
}
