#![forbid(unsafe_code)]

use android2rust_core::{
    AndroidJob, AndroidOperation, CaseMetadata, ForensicOptions, ProfileStore, ScheduleCadence, ScheduleSpec,
    ToolFamily, ValidationSeverity, build_args, build_batch_script, build_powershell_script, build_schtasks_command,
    build_shell_script, builtin_presets, decode_status_code, find_preset, format_command_line, inspect_artifact,
    parse_command_line, parse_recipe, serialize_recipe, validate_job,
};
use android2rust_report::{ReportFormat, parse_log_file_with_options, write_report, write_timeline};
use android2rust_runner::{CancelToken, detect_environment, run_job_blocking};
use android2rust_wpd::{
    CopyOutOptions, DirectoryMtpSource, LiveWpdSource, MobileFileQuery, MobileFileSearchProvider, MtpDeviceSource,
    WpdDevicesProvider, WpdError, copy_out, search_devices, write_wpd_entries_export,
};
use chrono::{DateTime, NaiveDate, Utc};
use guap_export::{ExportFormat, ExportOptions};
pub use guap_mcp::PolicyMode;
use guap_mcp::{ActionCommand, ActionRiskLevel, McpServerRegistry, McpToolError};
use guap_table::{GuapQuery, SortDirection, TableData, TableProvider, TableQuery, TableSchema};
use serde_json::{Map, Value, json};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info};

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "android2rust-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

const WPD_TOOL_NAMES: &[&str] = &[
    "android2rust_wpd_devices",
    "android2rust_mobile_file_search",
    "android2rust_wpd_delete",
];

fn get_legacy_tools_manifest() -> Value {
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
                    "preset": { "type": "string" },
                    "ab_password": { "type": "string", "description": "Optional passphrase for encrypted .ab pre-verification" },
                    "case_id": { "type": "string", "description": "Optional case identifier for chain-of-custody metadata" },
                    "evidence_id": { "type": "string", "description": "Optional evidence/exhibit identifier" },
                    "examiner": { "type": "string", "description": "Optional examiner name" }
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
                    "ab_password": { "type": "string", "description": "Optional passphrase for encrypted .ab inspection" },
                    "case_id": { "type": "string", "description": "Optional case identifier for chain-of-custody metadata" },
                    "evidence_id": { "type": "string", "description": "Optional evidence/exhibit identifier" },
                    "examiner": { "type": "string", "description": "Optional examiner name" },
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

pub fn build_wpd_registry(policy: PolicyMode) -> McpServerRegistry {
    let mut reg = McpServerRegistry::new(policy).with_server_info(SERVER_NAME, SERVER_VERSION);
    reg.register_action(Arc::new(WpdDevicesAction));
    reg.register_action(Arc::new(MobileFileSearchAction));
    reg.register_action(Arc::new(WpdDeleteAction));
    reg
}

pub fn get_tools_manifest() -> Value {
    let mut list = get_legacy_tools_manifest().as_array().cloned().unwrap_or_default();
    if let Value::Array(wpd_tools) = build_wpd_registry(PolicyMode::ReadOnlyOnly).list_tools() {
        list.extend(wpd_tools);
    }
    Value::Array(list)
}

struct WpdDevicesAction;

impl ActionCommand for WpdDevicesAction {
    fn command_id(&self) -> &'static str {
        "android2rust_wpd_devices"
    }

    fn description(&self) -> &'static str {
        "Enumerate connected Windows Portable Devices (WPD/MTP) or an offline synthetic directory fixture and their storages."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "source_dir": { "type": "string", "description": "Optional offline synthetic MTP directory fixture path" },
                "filter": { "type": "string", "description": "Optional tabular query filter expression over device columns" },
                "offset": { "type": "integer", "minimum": 0 },
                "limit": { "type": "integer", "minimum": 1 }
            }
        })
    }

    fn execute(&self, args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
        let source = select_wpd_source(args);
        match source.list_devices() {
            Ok(devices) => {
                let provider = WpdDevicesProvider::new(&devices);
                let tq = parse_mcp_table_query(&provider.schema(), args)?;
                let data = provider.query(&tq)?;
                Ok(json!({
                    "status": if devices.is_empty() { "no_devices" } else { "ok" },
                    "device_count": devices.len(),
                    "table": table_data_to_json(&data),
                    "devices": devices,
                }))
            }
            Err(err @ (WpdError::NoDevices | WpdError::UnsupportedPlatform | WpdError::AccessDenied(_))) => Ok(json!({
                "status": "unavailable",
                "error": err.to_string(),
                "device_count": 0,
                "devices": [],
            })),
            Err(err) => Err(McpToolError::ExecutionFailed(err.to_string())),
        }
    }
}

struct MobileFileSearchAction;

impl ActionCommand for MobileFileSearchAction {
    fn command_id(&self) -> &'static str {
        "android2rust_mobile_file_search"
    }

    fn description(&self) -> &'static str {
        "Search files across connected WPD/MTP devices or an offline synthetic directory fixture by wildcard/regex, size, date range, MIME/extension, with optional path-safe copy_out and Merkle-signed export."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "source_dir": { "type": "string", "description": "Optional offline synthetic MTP directory fixture path" },
                "pattern": { "type": "string", "description": "Wildcard (*, ?) or regex pattern" },
                "regex": { "type": "boolean", "default": false },
                "min_size": { "type": "integer", "minimum": 0 },
                "max_size": { "type": "integer", "minimum": 0 },
                "created_after": { "type": "string", "description": "RFC3339 or YYYY-MM-DD" },
                "created_before": { "type": "string", "description": "RFC3339 or YYYY-MM-DD" },
                "modified_after": { "type": "string", "description": "RFC3339 or YYYY-MM-DD" },
                "modified_before": { "type": "string", "description": "RFC3339 or YYYY-MM-DD" },
                "mime": { "type": "string", "description": "MIME type filter (e.g. image/jpeg or image/*)" },
                "ext": { "type": "string", "description": "Extension filter (e.g. jpg or .jpg)" },
                "device": { "type": "string", "description": "Device ID or friendly name substring" },
                "storage": { "type": "string", "description": "Storage name substring" },
                "path_prefix": { "type": "string", "description": "MTP folder path prefix" },
                "include_folders": { "type": "boolean", "default": false },
                "max_results": { "type": "integer", "minimum": 0 },
                "copy_out_dir": { "type": "string", "description": "Optional local destination directory for path-traversal-safe copy_out" },
                "preserve_tree": { "type": "boolean", "default": true },
                "overwrite": { "type": "boolean", "default": false },
                "export_path": { "type": "string", "description": "Optional path for guap-export output" },
                "export_format": { "type": "string", "description": "csv, tsv, json, jsonl, html, html-vertical, or markdown" },
                "filter": { "type": "string", "description": "Optional tabular query filter over WPD/MTP File Search columns" },
                "sort": { "type": "string", "description": "Optional tabular query sort spec (e.g. 'size_bytes desc')" },
                "columns": { "type": "array", "items": { "type": "string" } },
                "offset": { "type": "integer", "minimum": 0 },
                "limit": { "type": "integer", "minimum": 1 }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let query = MobileFileQuery {
            device_filter: args["device"].as_str().map(str::to_string),
            storage_filter: args["storage"].as_str().map(str::to_string),
            path_prefix: args["path_prefix"].as_str().map(str::to_string),
            pattern: args["pattern"].as_str().map(str::to_string),
            use_regex: args["regex"].as_bool().unwrap_or(false),
            min_size: args["min_size"].as_u64(),
            max_size: args["max_size"].as_u64(),
            created_after: parse_mcp_dt(args["created_after"].as_str())?,
            created_before: parse_mcp_dt(args["created_before"].as_str())?,
            modified_after: parse_mcp_dt(args["modified_after"].as_str())?,
            modified_before: parse_mcp_dt(args["modified_before"].as_str())?,
            content_type: args["mime"].as_str().map(str::to_string),
            extension: args["ext"].as_str().map(str::to_string),
            include_folders: args["include_folders"].as_bool().unwrap_or(false),
            max_results: args["max_results"].as_u64().map(|n| n as usize),
        };
        query
            .validate()
            .map_err(|e| McpToolError::InvalidParams(e.to_string()))?;

        let source = select_wpd_source(args);
        let entries = match search_devices(source.as_ref(), &query) {
            Ok(list) => list,
            Err(err @ (WpdError::NoDevices | WpdError::UnsupportedPlatform | WpdError::AccessDenied(_))) => {
                return Ok(json!({
                    "status": "unavailable",
                    "error": err.to_string(),
                    "matched_count": 0,
                    "entries": [],
                }));
            }
            Err(WpdError::InvalidQuery(msg)) => return Err(McpToolError::InvalidParams(msg)),
            Err(err) => return Err(McpToolError::ExecutionFailed(err.to_string())),
        };

        let provider = MobileFileSearchProvider::new(&entries);
        let tq = parse_mcp_table_query(&provider.schema(), args)?;
        let table_data = provider.query(&tq)?;

        let copied =
            if !dry_run && let Some(dest) = args["copy_out_dir"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
                let opts = CopyOutOptions {
                    preserve_tree: args["preserve_tree"].as_bool().unwrap_or(true),
                    overwrite: args["overwrite"].as_bool().unwrap_or(false),
                    max_copy_bytes: None,
                };
                Some(
                    copy_out(source.as_ref(), &entries, Path::new(dest), &opts).map_err(|e| match e {
                        WpdError::PathTraversal(m) | WpdError::InvalidQuery(m) => McpToolError::InvalidParams(m),
                        other => McpToolError::ExecutionFailed(other.to_string()),
                    })?,
                )
            } else {
                None
            };

        let custody =
            if !dry_run && let Some(out_str) = args["export_path"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
                let fmt_str = args["export_format"].as_str().unwrap_or("csv");
                let fmt = ExportFormat::parse(fmt_str).map_err(|e| McpToolError::InvalidParams(e.to_string()))?;
                let manifest = write_wpd_entries_export(&entries, Path::new(out_str), fmt, &ExportOptions::default())
                    .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;
                Some(manifest)
            } else {
                None
            };

        Ok(json!({
            "status": "ok",
            "dry_run": dry_run,
            "matched_count": entries.len(),
            "table": table_data_to_json(&table_data),
            "copied": copied,
            "custody_manifest": custody,
        }))
    }
}

struct WpdDeleteAction;

impl ActionCommand for WpdDeleteAction {
    fn command_id(&self) -> &'static str {
        "android2rust_wpd_delete"
    }

    fn description(&self) -> &'static str {
        "Delete an object on a connected WPD/MTP device. Mutating operation: requires AllowMutating policy and confirm_destructive=true."
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "device_id": { "type": "string", "description": "Target WPD device identifier" },
                "object_id": { "type": "string", "description": "Target WPD object identifier" }
            },
            "required": ["device_id", "object_id"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let device_id = args["device_id"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'device_id'".to_string()))?;
        let object_id = args["object_id"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'object_id'".to_string()))?;

        if dry_run {
            return Ok(json!({
                "status": "dry_run",
                "device_id": device_id,
                "object_id": object_id,
                "deleted": false,
            }));
        }

        let live = LiveWpdSource::new();
        live.delete_object(device_id, object_id)
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;
        Ok(json!({
            "status": "ok",
            "device_id": device_id,
            "object_id": object_id,
            "deleted": true,
        }))
    }
}

fn select_wpd_source(args: &Value) -> Box<dyn MtpDeviceSource> {
    if let Some(dir) = args["source_dir"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        Box::new(DirectoryMtpSource::new(dir))
    } else {
        Box::new(LiveWpdSource::new())
    }
}

fn parse_mcp_dt(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, McpToolError> {
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
    Err(McpToolError::InvalidParams(format!(
        "invalid timestamp '{s}'; expected RFC3339 or YYYY-MM-DD"
    )))
}

fn parse_mcp_table_query(schema: &TableSchema, args: &Value) -> Result<TableQuery, McpToolError> {
    let filter = match args["filter"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        Some(f) => Some(GuapQuery::parse_filter(f)?),
        None => None,
    };
    let sort = match args["sort"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        Some(spec) => {
            let parsed = GuapQuery::parse_sort(spec)?;
            let mut out = Vec::with_capacity(parsed.len());
            for (col, dir) in parsed {
                let idx = schema
                    .column_index(&col)
                    .ok_or_else(|| McpToolError::InvalidParams(format!("invalid sort column '{col}'")))?;
                out.push((idx, dir));
            }
            out
        }
        None => Vec::new(),
    };
    let columns = args["columns"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>()
    });
    let offset = args["offset"].as_u64().unwrap_or(0) as usize;
    let limit = args["limit"].as_u64().map(|n| n as usize);
    let _ = SortDirection::Asc;
    Ok(TableQuery {
        filter,
        sort,
        columns,
        offset,
        limit,
    })
}

fn table_data_to_json(data: &TableData) -> Value {
    let rows: Vec<Value> = data
        .rows
        .iter()
        .map(|row| {
            let mut obj = Map::new();
            obj.insert("row_id".to_string(), json!(row.id));
            for (idx, col) in data.schema.columns.iter().enumerate() {
                let val = row.cells.get(idx).map(|c| c.to_json_value()).unwrap_or(Value::Null);
                obj.insert(col.id.clone(), val);
            }
            Value::Object(obj)
        })
        .collect();
    json!({
        "tool_id": data.schema.tool_id,
        "title": data.schema.title,
        "total_rows": data.total_rows,
        "returned_rows": rows.len(),
        "columns": data.schema.columns,
        "rows": rows,
    })
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
                const MAX_RECIPE_BYTES: usize = 4 * 1024 * 1024;
                let file = std::fs::File::open(recipe_path)
                    .map_err(|e| format!("Failed reading .a2r recipe '{recipe_path}': {e}"))?;
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(
                    &mut std::io::Read::take(file, (MAX_RECIPE_BYTES + 1) as u64),
                    &mut bytes,
                )
                .map_err(|e| format!("Failed reading .a2r recipe '{recipe_path}': {e}"))?;
                if bytes.len() > MAX_RECIPE_BYTES {
                    return Err(format!(
                        ".a2r recipe '{recipe_path}' exceeds maximum allowed size ({} MiB).",
                        MAX_RECIPE_BYTES / (1024 * 1024)
                    ));
                }
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
            let mut job = resolve_job_from_args(args)?.with_dry_run();
            merge_forensic_args(&mut job, args);
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
            let mut job = resolve_job_from_args(args)?;
            merge_forensic_args(&mut job, args);
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
                merge_forensic_args(&mut job, args);
                if job.operation != AndroidOperation::InspectArtifact {
                    job = job.with_dry_run();
                }
                let errors: Vec<_> = validate_job(&job)
                    .into_iter()
                    .filter(|f| f.severity == ValidationSeverity::Error)
                    .collect();
                if !errors.is_empty() {
                    return Err(format!(
                        "Job validation errors prevented report generation: {}",
                        serde_json::to_string(&errors).unwrap_or_default()
                    ));
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

fn merge_forensic_args(job: &mut AndroidJob, args: &Value) {
    if let Some(cid) = args["case_id"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        job.forensic_opts.case_meta.case_id = Some(cid.to_string());
    }
    if let Some(eid) = args["evidence_id"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        job.forensic_opts.case_meta.evidence_id = Some(eid.to_string());
    }
    if let Some(ex) = args["examiner"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        job.forensic_opts.case_meta.examiner = Some(ex.to_string());
    }
    if let Some(pw) = args["ab_password"]
        .as_str()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("ANDROID2RUST_AB_PASSWORD").ok().filter(|s| !s.is_empty()))
    {
        job.forensic_opts.ab_password = Some(pw);
    }
}

pub fn handle_jsonrpc_request(req: &Value) -> Option<Value> {
    handle_jsonrpc_request_with_policy(req, PolicyMode::ReadOnlyOnly)
}

pub fn handle_jsonrpc_request_with_policy(req: &Value, policy: PolicyMode) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    debug!(method, "Received MCP JSON-RPC request");

    match method {
        m if m.starts_with("notifications/") => None,
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
            if WPD_TOOL_NAMES.contains(&tool_name) {
                return build_wpd_registry(policy).handle_jsonrpc_request(req);
            }
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
    run_stdio_server_with_policy(PolicyMode::ReadOnlyOnly)
}

pub fn run_stdio_server_with_policy(policy: PolicyMode) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        server = SERVER_NAME,
        version = SERVER_VERSION,
        ?policy,
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
                if let Some(resp) = handle_jsonrpc_request_with_policy(&req, policy) {
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
    fn mcp_initialize_and_tools_list_return_all_tools() {
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
        assert_eq!(tools.len(), 13);
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        for expected in [
            "android2rust_environment",
            "android2rust_presets",
            "android2rust_build_command",
            "android2rust_parse_command",
            "android2rust_decode_status",
            "android2rust_profiles",
            "android2rust_inspect_artifact",
            "android2rust_dry_run",
            "android2rust_run",
            "android2rust_report",
            "android2rust_wpd_devices",
            "android2rust_mobile_file_search",
            "android2rust_wpd_delete",
        ] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
        let search_tool = tools
            .iter()
            .find(|t| t["name"] == "android2rust_mobile_file_search")
            .unwrap();
        assert_eq!(search_tool["annotations"]["readOnlyHint"], true);
        assert_eq!(search_tool["annotations"]["destructiveHint"], false);

        let del_tool = tools.iter().find(|t| t["name"] == "android2rust_wpd_delete").unwrap();
        assert_eq!(del_tool["annotations"]["readOnlyHint"], false);
        assert_eq!(del_tool["annotations"]["destructiveHint"], true);
    }

    #[test]
    fn mcp_wpd_search_and_mutating_policy_gate_work() {
        let tmp = TempDir::new().unwrap();
        let dcim = tmp.path().join("DCIM").join("Camera");
        std::fs::create_dir_all(&dcim).unwrap();
        std::fs::write(dcim.join("IMG_001.jpg"), b"fakejpg").unwrap();
        std::fs::write(dcim.join("notes.txt"), b"hello").unwrap();

        let search_resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "android2rust_mobile_file_search",
                "arguments": {
                    "source_dir": tmp.path().display().to_string(),
                    "pattern": "*.jpg"
                }
            }
        }))
        .unwrap();
        assert_eq!(search_resp["result"]["isError"], false);
        let text = search_resp["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["matched_count"], 1);
        assert_eq!(payload["table"]["rows"][0]["filename"], "IMG_001.jpg");

        // ReadOnlyOnly policy blocks mutating delete with JSON-RPC -32003
        let blocked_ro = handle_jsonrpc_request_with_policy(
            &json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "android2rust_wpd_delete",
                    "arguments": { "device_id": "dev0", "object_id": "obj0", "confirm_destructive": true }
                }
            }),
            PolicyMode::ReadOnlyOnly,
        )
        .unwrap();
        assert_eq!(blocked_ro["error"]["code"], -32003);

        // AllowMutating still blocks if confirm_destructive is false/omitted
        let blocked_unconfirmed = handle_jsonrpc_request_with_policy(
            &json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "android2rust_wpd_delete",
                    "arguments": { "device_id": "dev0", "object_id": "obj0" }
                }
            }),
            PolicyMode::AllowMutating,
        )
        .unwrap();
        assert_eq!(blocked_unconfirmed["error"]["code"], -32003);
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

    #[test]
    fn mcp_dry_run_forwards_provenance_and_report_validates_jobs() {
        let tmp = TempDir::new().unwrap();
        let resp = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "android2rust_dry_run",
                "arguments": {
                    "op": "devices",
                    "case_id": "CASE-DRY-7",
                    "evidence_id": "EV-7",
                    "examiner": "Audit Bot"
                }
            }
        }))
        .unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let dry_val: Value = serde_json::from_str(text).unwrap();
        assert_eq!(dry_val["case_meta"]["case_id"], "CASE-DRY-7");

        // android2rust_report rejects invalid job lacking required target
        let invalid_rep = handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "android2rust_report",
                "arguments": {
                    "op": "install",
                    "output": tmp.path().join("bad.html").display().to_string()
                }
            }
        }))
        .unwrap();
        assert_eq!(invalid_rep["result"]["isError"], true);
    }
}
