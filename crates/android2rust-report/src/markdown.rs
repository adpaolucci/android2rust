use android2rust_core::format::{format_bytes, format_duration};
use android2rust_runner::RunResult;

fn md_cell(s: &str) -> String {
    s.replace(['\r', '\n'], " ").replace('|', "\\|")
}

pub fn render_markdown(result: &RunResult) -> String {
    let mut out = String::new();
    let mode = if result.dry_run {
        "Dry-Run Pre-Flight"
    } else {
        "Live / Forensic Execution"
    };
    let status = if result.cancelled {
        "Cancelled"
    } else if result.status_info.is_success {
        "Success"
    } else {
        "Failed"
    };

    out.push_str(&format!("# Android2Rust Audit Report: {}\n\n", result.job_name));
    if let Some(cid) = result
        .case_meta
        .case_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push_str(&format!("- **Case ID**: `{cid}`\n"));
    }
    if let Some(eid) = result
        .case_meta
        .evidence_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push_str(&format!("- **Evidence ID**: `{eid}`\n"));
    }
    if let Some(ex) = result
        .case_meta
        .examiner
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push_str(&format!("- **Examiner**: `{ex}`\n"));
    }
    out.push_str(&format!(
        "- **Status**: {status} (`{}`)\n",
        result.status_info.short_label
    ));
    out.push_str(&format!(
        "- **Tool / Operation**: `{}` / `{}`\n",
        result.tool.label(),
        result.operation.label()
    ));
    out.push_str(&format!("- **Mode**: {mode}\n"));
    out.push_str(&format!("- **Source / Artifact**: `{}`\n", result.source));
    out.push_str(&format!(
        "- **Target / Serial / Partition**: `{}`\n",
        result.destination
    ));
    out.push_str(&format!("- **Started**: `{}`\n", result.started_at));
    out.push_str(&format!("- **Ended**: `{}`\n", result.ended_at));
    out.push_str(&format!(
        "- **Duration**: `{}`\n",
        format_duration(result.duration_secs)
    ));
    out.push_str(&format!(
        "- **Log / Chain-of-Custody SHA-256**: `{}`\n",
        result.log_sha256
    ));
    if !result.log_sha512.is_empty() {
        out.push_str(&format!(
            "- **Log / Chain-of-Custody SHA-512**: `{}`\n",
            result.log_sha512
        ));
    }
    out.push('\n');

    out.push_str("## Command Line\n\n```bash\n");
    out.push_str(&result.command_line);
    out.push_str("\n```\n\n");

    out.push_str("## Status Breakdown\n\n");
    out.push_str(&format!("- {}\n", result.status_info.summary));
    for d in &result.status_info.details {
        out.push_str(&format!("- {d}\n"));
    }
    out.push('\n');

    out.push_str("## Summary Counters\n\n");
    out.push_str("| Metric | Value |\n");
    out.push_str("| :--- | ---: |\n");
    out.push_str(&format!("| Devices Seen | {} |\n", result.summary.devices_seen));
    out.push_str(&format!("| Properties Seen | {} |\n", result.summary.properties_seen));
    out.push_str(&format!("| Packages Seen | {} |\n", result.summary.packages_seen));
    out.push_str(&format!(
        "| Files Transferred | {} |\n",
        result.summary.files_transferred
    ));
    out.push_str(&format!(
        "| Bytes Processed | {} |\n",
        format_bytes(result.summary.bytes_processed)
    ));
    out.push_str(&format!("| Log Lines | {} |\n", result.summary.log_lines_seen));
    out.push_str(&format!("| Errors | {} |\n\n", result.summary.errors_seen));

    if let Some(forensic) = &result.forensic_report {
        out.push_str("## Offline Forensic Analysis\n\n");
        out.push_str(&format!("- **Detected Format**: {}\n", forensic.kind.label()));
        out.push_str(&format!("- **Artifact SHA-256**: `{}`\n", forensic.sha256));
        if !forensic.sha512.is_empty() {
            out.push_str(&format!("- **Artifact SHA-512**: `{}`\n", forensic.sha512));
        }
        if !forensic.timeline.is_empty() {
            out.push_str(&format!("- **Timeline Events**: `{}`\n", forensic.timeline.len()));
        }
        for (k, v) in &forensic.metadata {
            out.push_str(&format!("- **{k}**: `{v}`\n"));
        }
        if !forensic.permissions_or_tables.is_empty() {
            out.push_str("\n### Permissions / SQLite Tables\n\n");
            for item in &forensic.permissions_or_tables {
                out.push_str(&format!("- `{item}`\n"));
            }
        }
        if !forensic.warnings.is_empty() {
            out.push_str("\n### Forensic Warnings\n\n");
            for warn in &forensic.warnings {
                out.push_str(&format!("- `{warn}`\n"));
            }
        }
        out.push('\n');
    }

    if !result.errors.is_empty() {
        out.push_str("## Errors\n\n");
        for err in &result.errors {
            out.push_str(&format!("- `{err}`\n"));
        }
        out.push('\n');
    }

    if !result.file_actions.is_empty() {
        out.push_str("## Extracted Records\n\n");
        out.push_str("| Class | Size | Timestamp | Key / Path | Detail |\n");
        out.push_str("| :--- | ---: | :--- | :--- | :--- |\n");
        for rec in &result.file_actions {
            let sz = rec.size_bytes.map(format_bytes).unwrap_or_else(|| "-".to_string());
            let ts = rec.timestamp.as_deref().unwrap_or("-");
            let path_cell = md_cell(&rec.path).replace('`', "'");
            let detail_cell = md_cell(&rec.detail);
            out.push_str(&format!(
                "| {} | {} | {} | `{}` | {} |\n",
                rec.kind.label(),
                sz,
                ts,
                path_cell,
                detail_cell
            ));
        }
        out.push('\n');
    }

    out
}
