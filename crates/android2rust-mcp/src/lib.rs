#![forbid(unsafe_code)]

use android2rust_core::{
    AndroidJob, AndroidOperation, CaseMetadata, ForensicOptions, ProfileStore, ScheduleCadence, ScheduleSpec,
    ToolFamily, ValidationSeverity, build_args, build_batch_script, build_powershell_script, build_schtasks_command,
    build_shell_script, builtin_presets, decode_status_code, find_preset, format_command_line, inspect_artifact,
    parse_command_line, parse_recipe, serialize_recipe, validate_job,
};
use android2rust_report::{ReportFormat, parse_log_file_with_options, write_report, write_timeline};
use android2rust_runner::{CancelToken, detect_environment, run_job_blocking};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::Path;
use tracing::{debug, error, info};

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "android2rust-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn get_tools_manifest() -> Value {
    json!([
        {
            "name": "android2rust_environment",
            "description": "Detect host OS, adb and fastboot binary availability, versions, and configuration directory.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "android2rust_presets",
            "description": "List all 8 built-in ADB, Fastboot, and offline Android forensic inspection presets.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "android2rust_build_command",
            "description": "Build a validated ADB/Fastboot/Forensics command line plus optional .a2r, .bat, .ps1, .sh, and schtasks commands.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job": { "type": "object", "description": "Optional full AndroidJob JSON object" },
                    "op": { "type": "string", "description": "Optional operation slug (e.g. devices, install, pull, fastboot-flash, inspect)" },
                    "preset": { "type": "string", "description": "Optional built-in preset ID or name" },
                    "source": { "type": "string", "description": "Local file/artifact/APK/image or remote pull path" },
                    "target": { "type": "string", "description": "Destination path, package ID, partition, or shell cmd" },
                    "serial": { "type": "string", "description": "Target Android device serial (-s)" },
                    "slot": { "type": "string", "description": "Optional Fastboot A/B slot (--slot a | b | all)" },
                    "dry_run": { "type": "boolean", "description": "Enable non-destructive dry-run mode" },
                    "include_scripts": { "type": "boolean", "description": "Include .a2r, .bat, .ps1, and .sh outputs" },
                    "task_name": { "type": "string", "description": "Optional Task Scheduler task name to generate schtasks command" },
                    "cadence": { "type": "string", "description": "Schedule cadence: daily, weekly, hourly, onstart, onlogon" },
                    "start_time": { "type": "string", "description": "HH:MM start time (default 02:00)" }
                }
            }
        },
        {
            "name": "android2rust_parse_command",
            "description": "Parse a raw adb/fastboot command line or an .a2r recipe file path into a structured AndroidJob and validation diagnostics.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "Raw adb or fastboot command-line string" },
                    "recipe_path": { "type": "string", "description": "Path to an .a2r Android2Rust recipe file" }
                }
            }
        },
        {
            "name": "android2rust_decode_status",
            "description": "Decode an Android/ADB/Fastboot exit code or status string (e.g., INSTALL_FAILED_*, DEVICE_UNAUTHORIZED, FASTBOOT_LOCKED).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "Exit code integer or status string" }
                },
                "required": ["code"]
            }
        },
        {
            "name": "android2rust_profiles",
            "description": "Manage saved persistent Android2Rust job profiles (list, get, save, delete).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["list", "get", "save", "delete"] },
                    "name": { "type": "string", "description": "Profile name or ID" },
                    "description": { "type": "string", "description": "Profile description for save" },
                    "job": { "type": "object", "description": "AndroidJob JSON object for save" },
                    "store_dir": { "type": "string", "description": "Optional custom profile storage directory" }
                },
                "required": ["action"]
            }
        },
        {
            "name": "android2rust_inspect_artifact",
            "description": "Run pure-Rust offline forensic inspection on a local .apk, .ab (optionally decrypted), SQLite .db, ABX, bugreport .zip, XML, directory, or log dump.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Local path to artifact or extracted Android directory" },
                    "max_entries": { "type": "integer", "description": "Maximum entries to emit (default 2000)" },
                    "ab_password": { "type": "string", "description": "Optional passphrase to lawfully decrypt encrypted .ab backup payloads" },
                    "case_id": { "type": "string", "description": "Optional case identifier for chain-of-custody metadata" },
                    "evidence_id": { "type": "string", "description": "Optional evidence/exhibit identifier" },
                    "examiner": { "type": "string", "description": "Optional examiner name" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "android2rust_dry_run",
            "description": "Run a safe non-destructive pre-flight simulation (plus local artifact verification) without modifying connected Android devices.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job": { "type": "object" },
                    "op": { "type": "string", "description": "Optional operation slug (e.g. devices, install, pull, fastboot-flash, inspect)" },
                    "command": { "type": "string" },
                    "source": { "type": "string" },
                    "target": { "type": "string" },
                    "serial": { "type": "string" },
                    "slot": { "type": "string", "description": "Optional Fastboot A/B slot (--slot a | b | all)" },
                    "preset": { "type": "string" }
                }
            }
        },
        {
            "name": "android2rust_run",
            "description": "Execute an ADB, Fastboot, or forensic job. Refuses destructive operations (flash, erase, format, unlock, uninstall, restore) unless confirm_destructive is true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job": { "type": "object" },
                    "op": { "type": "string", "description": "Optional operation slug (e.g. devices, install, pull, fastboot-flash, inspect)" },
                    "command": { "type": "string" },
                    "source": { "type": "string" },
                    "target": { "type": "string" },
                    "serial": { "type": "string" },
                    "slot": { "type": "string", "description": "Optional Fastboot A/B slot (--slot a | b | all)" },
                    "preset": { "type": "string" },
                    "confirm_destructive": { "type": "boolean", "description": "Explicitly confirm destructive ADB/Fastboot execution" }
                }
            }
        },
        {
            "name": "android2rust_report",
            "description": "Generate an air-gapped offline HTML, JSON, Markdown, or timeline audit report from an artifact, log file, or dry-run job.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "log_path": { "type": "string", "description": "Path to existing log file or Android artifact (.apk/.ab/.db/ABX/bugreport .zip/.xml)" },
                    "output": { "type": "string", "description": "Output file path or directory when format is 'all'" },
                    "format": { "type": "string", "description": "html, json, markdown, timeline-csv, timeline-jsonl, or all" },
                    "timeline_output": { "type": "string", "description": "Optional secondary output file for chronological CSV or JSONL timeline export" },
                    "ab_password": { "type": "string", "description": "Optional passphrase for encrypted .ab backups" },
                    "case_id": { "type": "string", "description": "Optional case identifier for chain-of-custody header" },
                    "evidence_id": { "type": "string", "description": "Optional evidence identifier" },
                    "examiner": { "type": "string", "description": "Optional examiner name" },
                    "job": { "type": "object", "description": "Optional job to dry-run if log_path is omitted" },
                    "source": { "type": "string" },
                    "target": { "type": "string" }
                },
                "required": ["output"]
            }
        }
    ])
}

fn resolve_job_from_args(args: &Value) -> Result<AndroidJob, String> {
    let mut job = if args.get("job").is_some_and(Value::is_object) {
        serde_json::from_value::<AndroidJob>(args["job"].clone()).map_err(|e| format!("Invalid job JSON: {e}"))?
    } else if let Some(cmd) = args["command"].as_str() {
        parse_command_line(cmd).job
    } else if let Some(preset_name) = args["preset"].as_str() {
        find_preset(preset_name)
            .ok_or_else(|| format!("Unknown preset: {preset_name}"))?
            .job
    } else {
        AndroidJob::default()
    };

    if let Some(op_slug) = args["op"].as_str()
        && !op_slug.trim().is_empty()
    {
        let op = AndroidOperation::from_slug(op_slug).ok_or_else(|| format!("Unknown operation slug: {op_slug}"))?;
        job.operation = op;
        job.tool = op.default_tool();
    }
    if let Some(src) = args["source"].as_str()
        && !src.trim().is_empty()
    {
        job.source_path = src.trim().to_string();
    }
    if let Some(dst) = args["target"].as_str()
        && !dst.trim().is_empty()
    {
        job.target_path = dst.trim().to_string();
        if job.tool == ToolFamily::Fastboot {
            job.fastboot_opts.partition = dst.trim().to_string();
        }
    }
    if let Some(serial) = args["serial"].as_str()
        && !serial.trim().is_empty()
    {
        job.serial = serial.trim().to_string();
    }
    if let Some(slot) = args["slot"].as_str()
        && !slot.trim().is_empty()
    {
        job.fastboot_opts.slot = Some(slot.trim().to_string());
    }
    if let Some(dry) = args["dry_run"].as_bool()
        && dry
    {
        job = job.with_dry_run();
    }
    Ok(job)
}

pub fn call_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "android2rust_environment" => {
            let env = detect_environment();
            serde_json::to_value(env).map_err(|e| e.to_string())
        }
        "android2rust_presets" => {
            let presets = builtin_presets();
            serde_json::to_value(presets).map_err(|e| e.to_string())
        }
        "android2rust_build_command" => {
            let job = resolve_job_from_args(args)?;
            let findings = validate_job(&job);
            let cmd = format_command_line(&job);
            let (bin, argv) = build_args(&job);
            let include_scripts = args["include_scripts"].as_bool().unwrap_or(false);
            let recipe = include_scripts.then(|| serialize_recipe(&job));
            let bat = include_scripts.then(|| build_batch_script(&job));
            let ps1 = include_scripts.then(|| build_powershell_script(&job));
            let sh = include_scripts.then(|| build_shell_script(&job));
            let schtasks = args["task_name"].as_str().map(|tn| {
                let cadence = match args["cadence"]
                    .as_str()
                    .unwrap_or("daily")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "weekly" => ScheduleCadence::Weekly,
                    "hourly" => ScheduleCadence::Hourly,
                    "onstart" => ScheduleCadence::OnStart,
                    "onlogon" => ScheduleCadence::OnLogon,
                    _ => ScheduleCadence::Daily,
                };
                let spec = ScheduleSpec {
                    cadence,
                    start_time: args["start_time"].as_str().unwrap_or("02:00").to_string(),
                    days: None,
                    run_highest: true,
                };
                build_schtasks_command(tn, &cmd, &spec)
            });

            Ok(json!({
                "binary": bin,
                "command_line": cmd,
                "args": argv,
                "destructive": job.is_destructive(),
                "destructive_reasons": job.destructive_reasons(),
                "findings": findings,
                "job": job,
                "recipe": recipe,
                "batch_script": bat,
                "powershell_script": ps1,
                "shell_script": sh,
                "schtasks": schtasks,
            }))
        }
        "android2rust_parse_command" => {
            if let Some(recipe_path) = args["recipe_path"].as_str() {
                let bytes = std::fs::read(recipe_path)
                    .map_err(|e| format!("Failed reading .a2r recipe '{recipe_path}': {e}"))?;
                let (job, warnings) = parse_recipe(&bytes).map_err(|e| e.to_string())?;
                let findings = validate_job(&job);
                return Ok(json!({
                    "command_line": format_command_line(&job),
                    "warnings": warnings,
                    "findings": findings,
                    "job": job,
                }));
            }
            let raw = args["command"]
                .as_str()
                .ok_or("Provide either 'command' or 'recipe_path'")?;
            let parsed = parse_command_line(raw);
            let findings = validate_job(&parsed.job);
            Ok(json!({
                "command_line": format_command_line(&parsed.job),
                "unrecognized_tokens": parsed.unrecognized_tokens,
                "findings": findings,
                "job": parsed.job,
            }))
        }
        "android2rust_decode_status" => {
            let code_str = args["code"]
                .as_str()
                .map(str::to_string)
                .or_else(|| args["code"].as_i64().map(|n| n.to_string()))
                .ok_or("Missing required 'code'")?;
            let info = decode_status_code(&code_str);
            serde_json::to_value(info).map_err(|e| e.to_string())
        }
        "android2rust_profiles" => {
            let action = args["action"].as_str().ok_or("Missing required string 'action'")?;
            let store = match args["store_dir"].as_str() {
                Some(dir) if !dir.trim().is_empty() => ProfileStore::with_dir(dir),
                _ => ProfileStore::default_store(),
            };
            match action {
                "list" => {
                    let profiles = store.load_profiles().map_err(|e| e.to_string())?;
                    serde_json::to_value(profiles).map_err(|e| e.to_string())
                }
                "get" => {
                    let name = args["name"].as_str().ok_or("Missing 'name' for get")?;
                    let profile = store
                        .find_profile(name)
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| format!("Profile not found: {name}"))?;
                    serde_json::to_value(profile).map_err(|e| e.to_string())
                }
                "save" => {
                    let name = args["name"].as_str().ok_or("Missing 'name' for save")?;
                    let desc = args["description"].as_str().unwrap_or("");
                    let job = if args.get("job").is_some_and(Value::is_object) {
                        serde_json::from_value::<AndroidJob>(args["job"].clone())
                            .map_err(|e| format!("Invalid job JSON: {e}"))?
                    } else {
                        AndroidJob::default()
                    };
                    let profiles = store.upsert_profile(name, desc, job).map_err(|e| e.to_string())?;
                    serde_json::to_value(profiles).map_err(|e| e.to_string())
                }
                "delete" => {
                    let name = args["name"].as_str().ok_or("Missing 'name' for delete")?;
                    let (removed, profiles) = store.delete_profile(name).map_err(|e| e.to_string())?;
                    Ok(json!({ "removed": removed, "profiles": profiles }))
                }
                other => Err(format!("Unsupported profiles action: {other}")),
            }
        }
        "android2rust_inspect_artifact" => {
            let path_str = args["path"].as_str().ok_or("Missing required string 'path'")?;
            let opts = forensic_opts_from_args(args);
            let report = inspect_artifact(Path::new(path_str), &opts).map_err(|e| e.to_string())?;
            serde_json::to_value(report).map_err(|e| e.to_string())
        }
        "android2rust_dry_run" => {
            let job = resolve_job_from_args(args)?.with_dry_run();
            let errors: Vec<_> = validate_job(&job)
                .into_iter()
                .filter(|f| f.severity == ValidationSeverity::Error)
                .collect();
            if !errors.is_empty() {
                return Err(format!(
                    "Job validation errors prevented dry-run: {}",
                    serde_json::to_string(&errors).unwrap_or_default()
                ));
            }
            let res = run_job_blocking(&job, None, &CancelToken::new()).map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "android2rust_run" => {
            let job = resolve_job_from_args(args)?;
            let errors: Vec<_> = validate_job(&job)
                .into_iter()
                .filter(|f| f.severity == ValidationSeverity::Error)
                .collect();
            if !errors.is_empty() {
                return Err(format!(
                    "Job validation errors prevented execution: {}",
                    serde_json::to_string(&errors).unwrap_or_default()
                ));
            }
            let confirm_destructive = args["confirm_destructive"].as_bool().unwrap_or(false);
            if job.is_destructive() && !confirm_destructive {
                let reasons = job.destructive_reasons().join(", ");
                return Err(format!(
                    "SAFETY REFUSAL: Job includes destructive operation(s) ({reasons}). Re-run with android2rust_dry_run first or set confirm_destructive=true."
                ));
            }
            let res = run_job_blocking(&job, None, &CancelToken::new()).map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "android2rust_report" => {
            let out_str = args["output"].as_str().ok_or("Missing required string 'output'")?;
            let fmt_str = args["format"].as_str().unwrap_or("html");
            let format = ReportFormat::parse(fmt_str).map_err(|e| e.to_string())?;
            let opts = forensic_opts_from_args(args);

            let result = if let Some(log_path) = args["log_path"].as_str() {
                parse_log_file_with_options(Path::new(log_path), opts).map_err(|e| e.to_string())?
            } else {
                let mut job = resolve_job_from_args(args)?;
                if !opts.case_meta.is_empty() {
                    job.forensic_opts.case_meta = opts.case_meta;
                }
                if opts.ab_password.is_some() {
                    job.forensic_opts.ab_password = opts.ab_password;
                }
                if job.operation != AndroidOperation::InspectArtifact {
                    job = job.with_dry_run();
                }
                run_job_blocking(&job, None, &CancelToken::new()).map_err(|e| e.to_string())?
            };

            let written = write_report(&result, format, Path::new(out_str)).map_err(|e| e.to_string())?;
            let timeline_written =
                if let Some(tl_str) = args["timeline_output"].as_str().filter(|s| !s.trim().is_empty()) {
                    Some(write_timeline(&result, Path::new(tl_str)).map_err(|e| e.to_string())?)
                } else {
                    None
                };
            Ok(json!({
                "status": "success",
                "files_written": written,
                "timeline_written": timeline_written,
                "exit_code": result.exit_code,
                "log_sha256": result.log_sha256,
                "log_sha512": result.log_sha512,
            }))
        }
        other => Err(format!("Unknown android2rust MCP tool: {other}")),
    }
}

fn forensic_opts_from_args(args: &Value) -> ForensicOptions {
    let mut opts = ForensicOptions::default();
    if let Some(m) = args["max_entries"].as_u64() {
        opts.max_entries = m as usize;
    }
    opts.case_meta = CaseMetadata {
        case_id: args["case_id"].as_str().map(str::to_string),
        evidence_id: args["evidence_id"].as_str().map(str::to_string),
        examiner: args["examiner"].as_str().map(str::to_string),
    };
    opts.ab_password = args["ab_password"]
        .as_str()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("ANDROID2RUST_AB_PASSWORD").ok().filter(|s| !s.is_empty()));
    opts
}

pub fn handle_jsonrpc_request(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    debug!(method, "Received MCP JSON-RPC request");

    match method {
        "notifications/initialized" | "notifications/cancelled" => None,
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": get_tools_manifest()
            }
        })),
        "tools/call" => {
            let params = &req["params"];
            let tool_name = params["name"].as_str().unwrap_or("");
            let args = &params["arguments"];
            let (text, is_err) = match call_tool(tool_name, args) {
                Ok(val) => (serde_json::to_string_pretty(&val).unwrap_or_default(), false),
                Err(msg) => (msg, true),
            };
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }],
                    "isError": is_err
                }
            }))
        }
        _ => id.map(|req_id| {
            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {method}")
                }
            })
        }),
    }
}

pub fn run_stdio_server() -> Result<(), Box<dyn std::error::Error>> {
    info!(
        server = SERVER_NAME,
        version = SERVER_VERSION,
        "Starting android2rust MCP stdio server"
    );
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                error!(error = %e, "Failed reading MCP stdin line");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(req) => {
                if let Some(resp) = handle_jsonrpc_request(&req) {
                    let out = serde_json::to_string(&resp)?;
                    writeln!(stdout, "{out}")?;
                    stdout.flush()?;
                }
            }
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                writeln!(stdout, "{}", serde_json::to_string(&err_resp)?)?;
                stdout.flush()?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn mcp_initialize_and_tools_list_return_ten_tools() {
        let init_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        }))
        .unwrap();
        assert_eq!(init_resp["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);

        let list_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }))
        .unwrap();
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 10);
    }

    #[test]
    fn mcp_blocks_destructive_run_without_explicit_confirmation() {
        let resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "android2rust_run",
                "arguments": {
                    "preset": "fastboot-flash-image",
                    "source": "boot.img",
                    "target": "boot"
                }
            }
        }))
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let msg = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(msg.contains("confirm_destructive=true"));
    }

    #[test]
    fn mcp_inspects_artifact_and_writes_report() {
        let tmp = TempDir::new().unwrap();
        let xml = tmp.path().join("prefs.xml");
        std::fs::write(
            &xml,
            r#"<?xml version="1.0"?><map><string name="token">abc</string></map>"#,
        )
        .unwrap();

        let inspect_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "android2rust_inspect_artifact",
                "arguments": {
                    "path": xml.display().to_string()
                }
            }
        }))
        .unwrap();
        assert_eq!(inspect_resp["result"]["isError"], false);

        let out_html = tmp.path().join("audit.html");
        let out_tl = tmp.path().join("timeline.csv");
        let rep_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "android2rust_report",
                "arguments": {
                    "log_path": xml.display().to_string(),
                    "output": out_html.display().to_string(),
                    "format": "html",
                    "timeline_output": out_tl.display().to_string(),
                    "case_id": "CASE-MCP-1",
                    "evidence_id": "EV-99",
                    "examiner": "MCP-Audit"
                }
            }
        }))
        .unwrap();
        assert_eq!(rep_resp["result"]["isError"], false);
        assert!(out_html.is_file());
        assert!(out_tl.is_file());
        let html = std::fs::read_to_string(&out_html).unwrap();
        assert!(html.contains("CASE-MCP-1"));
        let text = rep_resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("log_sha512"));
    }

    #[test]
    fn mcp_build_command_supports_op_and_slot_arguments() {
        let resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "android2rust_build_command",
                "arguments": {
                    "op": "fastboot-flash",
                    "slot": "b",
                    "target": "init_boot",
                    "source": "init_boot.img"
                }
            }
        }))
        .unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            parsed["command_line"],
            "fastboot --slot b flash init_boot init_boot.img"
        );
        assert_eq!(parsed["destructive"], true);
    }
}
