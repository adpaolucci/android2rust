use android2rust_core::TimelineEvent;
use android2rust_runner::RunResult;
use anyhow::Result;

fn normalize_telemetry_ts(ts: &str) -> String {
    let b = ts.as_bytes();
    if b.len() >= 19 && b[4] == b'-' && b[7] == b'-' && b[10] == b' ' {
        format!("{}Z", ts.replacen(' ', "T", 1))
    } else {
        ts.to_string()
    }
}

pub fn collect_timeline_events(result: &RunResult) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    if let Some(rep) = &result.forensic_report {
        events.extend(rep.timeline.iter().cloned());
    }
    for rec in &result.file_actions {
        if let Some(ts) = rec.timestamp.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            events.push(TimelineEvent {
                timestamp: normalize_telemetry_ts(ts),
                source: "Run Telemetry".to_string(),
                category: rec.kind.label().to_string(),
                target: rec.path.clone(),
                detail: rec.detail.clone(),
            });
        }
    }
    events.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    events.dedup();
    events
}

fn csv_cell(raw: &str) -> String {
    if raw.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", raw.replace('"', "\"\""))
    } else {
        raw.to_string()
    }
}

pub fn render_timeline_csv(result: &RunResult) -> String {
    let mut out = String::from("timestamp,source,category,target,detail\n");
    for ev in collect_timeline_events(result) {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_cell(&ev.timestamp),
            csv_cell(&ev.source),
            csv_cell(&ev.category),
            csv_cell(&ev.target),
            csv_cell(&ev.detail)
        ));
    }
    out
}

pub fn render_timeline_jsonl(result: &RunResult) -> Result<String> {
    let mut out = String::new();
    for ev in collect_timeline_events(result) {
        out.push_str(&serde_json::to_string(&ev)?);
        out.push('\n');
    }
    Ok(out)
}
