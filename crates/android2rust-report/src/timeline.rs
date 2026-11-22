use android2rust_core::TimelineEvent;
use android2rust_runner::RunResult;
use anyhow::Result;

fn normalize_telemetry_ts(ts: &str) -> String {
    let s = ts.trim();
    let b = s.as_bytes();
    if b.len() >= 19
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[10] == b' '
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[13] == b':'
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[16] == b':'
        && b[17..19].iter().all(u8::is_ascii_digit)
    {
        s.replacen(' ', "T", 1)
    } else {
        s.to_string()
    }
}

fn has_leading_year(ts: &str) -> bool {
    let b = ts.as_bytes();
    b.len() >= 5 && b[0..4].iter().all(u8::is_ascii_digit) && b[4] == b'-'
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
        has_leading_year(&b.timestamp)
            .cmp(&has_leading_year(&a.timestamp))
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    events.dedup();
    events
}

fn csv_cell(raw: &str) -> String {
    let neutralized = if raw.starts_with(['=', '+', '-', '@', '\t', '\r'])
        || raw.trim_start_matches(' ').starts_with(['=', '+', '-', '@'])
    {
        format!("'{raw}")
    } else {
        raw.to_string()
    };
    if neutralized.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", neutralized.replace('"', "\"\""))
    } else {
        neutralized
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
