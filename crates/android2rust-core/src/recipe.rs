use crate::model::{AndroidJob, AndroidOperation, ToolFamily, TransportMode};
use anyhow::{Context, Result};

/// Serializes an [`AndroidJob`] to a portable `.a2r` recipe JSON document.
pub fn serialize_recipe(job: &AndroidJob) -> String {
    serde_json::to_string_pretty(job).unwrap_or_else(|_| "{}".to_string())
}

/// Parses an `.a2r` recipe file (UTF-8 JSON or simple `KEY=VALUE` lines).
pub fn parse_recipe(bytes: &[u8]) -> Result<(AndroidJob, Vec<String>)> {
    let text = decode_text_bytes(bytes)?;
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let job: AndroidJob = serde_json::from_str(trimmed).context("Invalid JSON .a2r recipe")?;
        return Ok((job, Vec::new()));
    }

    let mut job = AndroidJob::default();
    let mut warnings = Vec::new();
    for (idx, raw) in trimmed.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            warnings.push(format!("Line {}: ignored unparsed entry '{line}'", idx + 1));
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "name" => job.name = val.to_string(),
            "description" => job.description = val.to_string(),
            "tool" => {
                job.tool = match val.to_ascii_lowercase().as_str() {
                    "fastboot" => ToolFamily::Fastboot,
                    "forensics" | "inspect" => ToolFamily::Forensics,
                    _ => ToolFamily::Adb,
                };
            }
            "operation" => {
                if let Some(op) = AndroidOperation::from_slug(val) {
                    job.operation = op;
                    job.tool = op.default_tool();
                } else {
                    warnings.push(format!("Line {}: unknown operation '{val}'", idx + 1));
                }
            }
            "serial" => {
                job.serial = val.to_string();
                if !val.is_empty() {
                    job.transport = TransportMode::Serial(val.to_string());
                }
            }
            "source" | "source_path" => job.source_path = val.to_string(),
            "target" | "target_path" => job.target_path = val.to_string(),
            "partition" => job.fastboot_opts.partition = val.to_string(),
            "slot" => {
                job.fastboot_opts.slot = if val.is_empty() { None } else { Some(val.to_string()) };
            }
            "case_id" => {
                job.forensic_opts.case_meta.case_id = if val.is_empty() { None } else { Some(val.to_string()) };
            }
            "evidence_id" => {
                job.forensic_opts.case_meta.evidence_id = if val.is_empty() { None } else { Some(val.to_string()) };
            }
            "examiner" => {
                job.forensic_opts.case_meta.examiner = if val.is_empty() { None } else { Some(val.to_string()) };
            }
            "dry_run" => job.dry_run = val.eq_ignore_ascii_case("true") || val == "1",
            _ => warnings.push(format!("Line {}: unknown recipe key '{key}'", idx + 1)),
        }
    }
    Ok((job, warnings))
}

fn decode_text_bytes(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let mut units = Vec::with_capacity((bytes.len() - 2) / 2);
        for chunk in bytes[2..].as_chunks::<2>().0 {
            units.push(u16::from_le_bytes(*chunk));
        }
        return Ok(String::from_utf16(&units)?);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let mut units = Vec::with_capacity((bytes.len() - 2) / 2);
        for chunk in bytes[2..].as_chunks::<2>().0 {
            units.push(u16::from_be_bytes(*chunk));
        }
        return Ok(String::from_utf16(&units)?);
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Ok(String::from_utf8_lossy(&bytes[3..]).into_owned());
    }
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_json_and_kv_recipes() {
        let mut job = AndroidJob {
            name: "Pull Logs".to_string(),
            operation: AndroidOperation::Pull,
            source_path: "/sdcard/logs.txt".to_string(),
            target_path: r"C:\Temp\logs.txt".to_string(),
            ..Default::default()
        };
        job.transfer_opts.preserve_timestamps = true;

        let serialized = serialize_recipe(&job);
        let (parsed, warnings) = parse_recipe(serialized.as_bytes()).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(parsed, job);

        let kv = "name=Boot Flash\noperation=fastboot-flash\nsource=boot.img\npartition=boot\nslot=b\n";
        let (parsed_kv, kv_warn) = parse_recipe(kv.as_bytes()).unwrap();
        assert!(kv_warn.is_empty());
        assert_eq!(parsed_kv.operation, AndroidOperation::FastbootFlash);
        assert_eq!(parsed_kv.fastboot_opts.slot.as_deref(), Some("b"));

        let kv_meta = "operation=inspect\nsource=ev.apk\ncase_id=IR-7\nevidence_id=EV-3\nexaminer=Ada\n";
        let mut utf16be = vec![0xFE, 0xFF];
        for u in kv_meta.encode_utf16() {
            utf16be.extend_from_slice(&u.to_be_bytes());
        }
        let (parsed_be, be_warn) = parse_recipe(&utf16be).unwrap();
        assert!(be_warn.is_empty());
        assert_eq!(parsed_be.operation, AndroidOperation::InspectArtifact);
        assert_eq!(parsed_be.forensic_opts.case_meta.case_id.as_deref(), Some("IR-7"));
        assert_eq!(parsed_be.forensic_opts.case_meta.evidence_id.as_deref(), Some("EV-3"));
        assert_eq!(parsed_be.forensic_opts.case_meta.examiner.as_deref(), Some("Ada"));
    }
}
