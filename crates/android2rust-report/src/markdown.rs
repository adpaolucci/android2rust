use android2rust_core::format::{format_bytes, format_duration};
use android2rust_runner::RunResult;

fn md_cell(s: &str) -> String {
    s.replace(['\r', '\n'], " ").replace('|', "\\|")
}

fn max_backtick_run(s: &str) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    for ch in s.chars() {
        if ch == '`' {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

fn md_code(s: &str) -> String {
    let clean = s.replace(['\r', '\n'], " ");
    let fence = "`".repeat(max_backtick_run(&clean) + 1);
    if clean.starts_with('`') || clean.ends_with('`') {
        format!("{fence} {clean} {fence}")
    } else {
        format!("{fence}{clean}{fence}")
    }
}

fn md_fence_delim(s: &str) -> String {
    "`".repeat(max_backtick_run(s).max(2) + 1)
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

    out.push_str(&format!(
        "# Android2Rust Audit Report: {}\n\n",
        result.job_name.replace(['\r', '\n'], " ")
    ));
    if let Some(cid) = result
        .case_meta
        .case_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push_str(&format!("- **Case ID**: {}\n", md_code(cid)));
    }
    if let Some(eid) = result
        .case_meta
        .evidence_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push_str(&format!("- **Evidence ID**: {}\n", md_code(eid)));
    }
    if let Some(ex) = result
        .case_meta
        .examiner
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        out.push_str(&format!("- **Examiner**: {}\n", md_code(ex)));
    }
    out.push_str(&format!(
        "- **Status**: {status} ({})\n",
        md_code(&result.status_info.short_label)
    ));
    out.push_str(&format!(
        "- **Tool / Operation**: {} / {}\n",
        md_code(result.tool.label()),
        md_code(result.operation.label())
    ));
    out.push_str(&format!("- **Mode**: {mode}\n"));
    out.push_str(&format!("- **Source / Artifact**: {}\n", md_code(&result.source)));
    out.push_str(&format!(
        "- **Target / Serial / Partition**: {}\n",
        md_code(&result.destination)
    ));
    out.push_str(&format!("- **Started**: {}\n", md_code(&result.started_at)));
    out.push_str(&format!("- **Ended**: {}\n", md_code(&result.ended_at)));
    out.push_str(&format!(
        "- **Duration**: {}\n",
        md_code(&format_duration(result.duration_secs))
    ));
    out.push_str(&format!(
        "- **Log / Chain-of-Custody SHA-256**: {}\n",
        md_code(&result.log_sha256)
    ));
    if !result.log_sha512.is_empty() {
        out.push_str(&format!(
            "- **Log / Chain-of-Custody SHA-512**: {}\n",
            md_code(&result.log_sha512)
        ));
    }
    out.push('\n');

    let cmd_clean = result.command_line.replace(['\r', '\n'], " ");
    let cmd_fence = md_fence_delim(&cmd_clean);
    out.push_str(&format!(
        "## Command Line\n\n{cmd_fence}bash\n{cmd_clean}\n{cmd_fence}\n\n"
    ));

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
        out.push_str(&format!("- **Artifact SHA-256**: {}\n", md_code(&forensic.sha256)));
        if !forensic.sha512.is_empty() {
            out.push_str(&format!("- **Artifact SHA-512**: {}\n", md_code(&forensic.sha512)));
        }
        if !forensic.timeline.is_empty() {
            out.push_str(&format!("- **Timeline Events**: `{}`\n", forensic.timeline.len()));
        }
        for (k, v) in &forensic.metadata {
            out.push_str(&format!("- **{}**: {}\n", md_cell(k), md_code(v)));
        }
        if !forensic.permissions_or_tables.is_empty() {
            out.push_str("\n### Permissions / SQLite Tables\n\n");
            for item in &forensic.permissions_or_tables {
                out.push_str(&format!("- {}\n", md_code(item)));
            }
        }
        if !forensic.warnings.is_empty() {
            out.push_str("\n### Forensic Warnings\n\n");
            for warn in &forensic.warnings {
                out.push_str(&format!("- {}\n", md_code(warn)));
            }
        }
        out.push('\n');
    }

    let timeline_events = crate::timeline::collect_timeline_events(result);
    if !timeline_events.is_empty() {
        const MAX_MD_TIMELINE: usize = 500;
        let total = timeline_events.len();
        out.push_str(&format!("## Chronological Timeline ({total})\n\n"));
        if total > MAX_MD_TIMELINE {
            out.push_str(&format!(
                "*Showing first {MAX_MD_TIMELINE} of {total} timeline events (export Timeline CSV/JSONL for full sequence).*\n\n"
            ));
        }
        out.push_str("| Timestamp | Source | Category | Target | Detail |\n");
        out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
        for ev in timeline_events.iter().take(MAX_MD_TIMELINE) {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                md_code(&md_cell(&ev.timestamp)),
                md_cell(&ev.source),
                md_cell(&ev.category),
                md_code(&md_cell(&ev.target)),
                md_cell(&ev.detail)
            ));
        }
        out.push('\n');
    }

    if !result.errors.is_empty() {
        out.push_str("## Errors\n\n");
        for err in &result.errors {
            out.push_str(&format!("- {}\n", md_code(err)));
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
            let path_cell = md_code(&md_cell(&rec.path));
            let detail_cell = md_cell(&rec.detail);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                rec.kind.label(),
                sz,
                md_cell(ts),
                path_cell,
                detail_cell
            ));
        }
        out.push('\n');
    }

    out
}
