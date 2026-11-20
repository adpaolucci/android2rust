use android2rust_core::format::{format_bytes, format_duration};
use android2rust_runner::RunResult;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render_html(result: &RunResult) -> String {
    let status_badge = if result.cancelled {
        ("CANCELLED", "#b45309")
    } else if result.status_info.is_success {
        ("SUCCESS", "#15803d")
    } else {
        ("FAILED", "#b91c1c")
    };

    let mode_badge = if result.dry_run {
        "DRY-RUN PRE-FLIGHT"
    } else {
        result.tool.label()
    };

    let detail_items: String = result
        .status_info
        .details
        .iter()
        .map(|d| format!("<li>{}</li>", esc(d)))
        .collect::<Vec<_>>()
        .join("");

    let action_rows: String = result
        .file_actions
        .iter()
        .map(|rec| {
            let size_txt = rec.size_bytes.map(format_bytes).unwrap_or_else(|| "-".to_string());
            let ts_txt = rec.timestamp.as_deref().unwrap_or("-");
            format!(
                "<tr data-kind=\"{}\"><td><span class=\"tag\">{}</span></td><td class=\"num\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                esc(rec.kind.label()),
                esc(rec.kind.label()),
                esc(&size_txt),
                esc(ts_txt),
                esc(&rec.path),
                esc(&rec.detail)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let error_section = if result.errors.is_empty() {
        "<p class=\"muted\">No errors reported.</p>".to_string()
    } else {
        let items: String = result
            .errors
            .iter()
            .map(|e| format!("<li><code>{}</code></li>", esc(e)))
            .collect::<Vec<_>>()
            .join("\n");
        format!("<ul class=\"errors\">{items}</ul>")
    };

    let forensic_card = if let Some(rep) = &result.forensic_report {
        let meta_rows: String = rep
            .metadata
            .iter()
            .map(|(k, v)| format!("<tr><td>{}</td><td class=\"mono\">{}</td></tr>", esc(k), esc(v)))
            .collect::<Vec<_>>()
            .join("");
        let perms = if rep.permissions_or_tables.is_empty() {
            String::new()
        } else {
            let items: String = rep
                .permissions_or_tables
                .iter()
                .map(|p| format!("<li><code>{}</code></li>", esc(p)))
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<h3 style=\"margin:12px 0 6px 0;font-size:13px;\">Extracted Permissions / SQLite Tables</h3><ul>{items}</ul>"
            )
        };
        format!(
            "<div class=\"card\"><h2 style=\"margin:0 0 8px 0;font-size:15px;\">Pure-Rust Forensic Inspection ({})</h2>\
             <div class=\"muted\">Artifact SHA-256: <span class=\"mono\">{}</span></div>\
             <table style=\"margin-top:8px;\"><thead><tr><th>Attribute</th><th>Value</th></tr></thead><tbody>{meta_rows}</tbody></table>\
             {perms}</div>",
            esc(rep.kind.label()),
            esc(&rep.sha256),
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Android2Rust Audit Report - {title}</title>
<style>
  :root {{
    --bg: #f3f4f6;
    --card: #ffffff;
    --fg: #111827;
    --muted: #6b7280;
    --border: #d1d5db;
    --accent: #059669;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }}
  body.dark {{
    --bg: #0f172a;
    --card: #1e293b;
    --fg: #e2e8f0;
    --muted: #94a3b8;
    --border: #334155;
    --accent: #34d399;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: "Segoe UI", system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); padding: 24px; }}
  .wrap {{ max-width: 1200px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 16px; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }}
  .badge {{ display: inline-block; padding: 3px 9px; border-radius: 4px; font-size: 12px; font-weight: 700; color: #fff; background: {status_color}; }}
  .mode {{ display: inline-block; padding: 3px 9px; border-radius: 4px; font-size: 12px; font-weight: 600; border: 1px solid var(--border); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr)); gap: 12px; }}
  .kpi-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
  .kpi-val {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
  .cmd {{ font-family: var(--mono); font-size: 12px; background: rgba(127,127,127,0.1); padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ border-bottom: 1px solid var(--border); padding: 7px 8px; text-align: left; vertical-align: top; }}
  th {{ font-weight: 600; color: var(--muted); }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .mono {{ font-family: var(--mono); word-break: break-all; }}
  .tag {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; border: 1px solid var(--border); }}
  .toolbar {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }}
  input[type="text"], button {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--card); color: var(--fg); font-size: 13px; }}
  button {{ cursor: pointer; }}
  .muted {{ color: var(--muted); font-size: 13px; }}
  .errors {{ color: #dc2626; font-size: 13px; }}
</style>
</head>
<body class="dark">
<div class="wrap">
  <div class="card header">
    <div>
      <h1 style="margin:0 0 6px 0;font-size:20px;">Android2Rust Audit Report &mdash; {title}</h1>
      <div class="muted">Source/Artifact: <span class="mono">{source}</span> &rarr; Target: <span class="mono">{dest}</span></div>
      <div class="muted">Started: {started} | Ended: {ended} | Duration: {duration}</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;">
      <span class="mode">{mode_badge}</span>
      <span class="badge">{status_text} ({exit_code})</span>
      <button onclick="document.body.classList.toggle('dark')">Toggle Theme</button>
    </div>
  </div>

  <div class="grid">
    <div class="card"><div class="kpi-label">Status</div><div class="kpi-val">{status_label}</div></div>
    <div class="card"><div class="kpi-label">Devices / Packages</div><div class="kpi-val">{devices} / {packages}</div></div>
    <div class="card"><div class="kpi-label">Props / Transfers</div><div class="kpi-val">{props} / {transfers}</div></div>
    <div class="card"><div class="kpi-label">Bytes Processed</div><div class="kpi-val">{bytes_proc}</div></div>
    <div class="card"><div class="kpi-label">Errors</div><div class="kpi-val">{err_total}</div></div>
  </div>

  <div class="card">
    <h2 style="margin:0 0 8px 0;font-size:15px;">Command Line &amp; Status Diagnostics</h2>
    <div class="cmd" id="cmdline">{cmd}</div>
    <p style="margin:10px 0 4px 0;font-size:13px;">{status_summary}</p>
    <ul style="margin:4px 0 0 18px;font-size:13px;">{detail_items}</ul>
  </div>

  {forensic_card}

  <div class="card">
    <h2 style="margin:0 0 8px 0;font-size:15px;">Errors ({error_count})</h2>
    {error_section}
  </div>

  <div class="card">
    <h2 style="margin:0 0 8px 0;font-size:15px;">Parsed Device, Package, Property &amp; Forensic Records ({action_count})</h2>
    <div class="toolbar">
      <input type="text" id="filterBox" placeholder="Filter by class, key, path, or detail..." oninput="filterRows()" style="min-width:280px;">
    </div>
    <table>
      <thead><tr><th>Class</th><th class="num">Size</th><th>Timestamp</th><th>Key / Path</th><th>Detail</th></tr></thead>
      <tbody id="actionBody">{action_rows}</tbody>
    </table>
  </div>

  <div class="card muted">
    Air-gapped pure-Rust report generated by <strong>android2rust</strong> &bull; Log SHA-256: <span class="mono">{sha256}</span>
  </div>
</div>
<script>
function filterRows() {{
  var q = document.getElementById('filterBox').value.toLowerCase();
  var rows = document.getElementById('actionBody').getElementsByTagName('tr');
  for (var i = 0; i < rows.length; i++) {{
    var txt = rows[i].innerText.toLowerCase();
    rows[i].style.display = txt.indexOf(q) !== -1 ? '' : 'none';
  }}
}}
</script>
</body>
</html>
"#,
        title = esc(&result.job_name),
        source = esc(&result.source),
        dest = esc(&result.destination),
        started = esc(&result.started_at),
        ended = esc(&result.ended_at),
        duration = esc(&format_duration(result.duration_secs)),
        mode_badge = esc(mode_badge),
        status_text = status_badge.0,
        status_color = status_badge.1,
        exit_code = result.exit_code,
        status_label = esc(&result.status_info.short_label),
        devices = result.summary.devices_seen,
        packages = result.summary.packages_seen,
        props = result.summary.properties_seen,
        transfers = result.summary.files_transferred,
        bytes_proc = esc(&format_bytes(result.summary.bytes_processed)),
        err_total = result.summary.errors_seen,
        cmd = esc(&result.command_line),
        status_summary = esc(&result.status_info.summary),
        detail_items = detail_items,
        forensic_card = forensic_card,
        error_count = result.errors.len(),
        error_section = error_section,
        action_count = result.file_actions.len(),
        action_rows = action_rows,
        sha256 = esc(&result.log_sha256),
    )
}
