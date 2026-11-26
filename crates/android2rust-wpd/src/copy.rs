use std::fs::OpenOptions;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use crate::error::WpdError;
use crate::model::{CopyOutOptions, CopyOutRecord, WpdObjectEntry};
use crate::source::MtpDeviceSource;

const RESERVED_WINDOWS_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
    "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn has_forbidden_chars(s: &str) -> bool {
    s.chars().any(|c| {
        c == '\0'
            || c.is_ascii_control()
            || ('\u{202A}'..='\u{202E}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
            || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
    })
}

fn sanitize_component(raw: &str) -> Result<String, WpdError> {
    if raw.is_empty() || raw == "." || raw == ".." {
        return Err(WpdError::PathTraversal(format!(
            "invalid empty or relative path component '{raw}'"
        )));
    }
    if has_forbidden_chars(raw) {
        return Err(WpdError::PathTraversal(format!(
            "forbidden control, BiDi, ADS colon, or wildcard character in component '{raw}'"
        )));
    }
    let trimmed = raw.trim_end_matches(['.', ' ']);
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return Err(WpdError::PathTraversal(format!(
            "component '{raw}' reduces to empty/relative segment after trimming trailing dots/spaces"
        )));
    }
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    if RESERVED_WINDOWS_NAMES.iter().any(|res| res.eq_ignore_ascii_case(stem)) {
        Ok(format!("_{trimmed}"))
    } else {
        Ok(trimmed.to_string())
    }
}

fn validate_raw_path_string(raw: &str, allow_separators: bool) -> Result<Vec<String>, WpdError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WpdError::PathTraversal("empty MTP path or filename".to_string()));
    }
    if has_forbidden_chars(trimmed) {
        return Err(WpdError::PathTraversal(format!(
            "forbidden control, BiDi, ADS colon, or invalid character in '{trimmed}'"
        )));
    }
    if trimmed.starts_with(r"\\") || trimmed.starts_with("//") {
        return Err(WpdError::PathTraversal(format!(
            "UNC path prefix rejected: '{trimmed}'"
        )));
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(WpdError::PathTraversal(format!(
            "Windows drive letter prefix rejected: '{trimmed}'"
        )));
    }
    if !allow_separators && (trimmed.contains('/') || trimmed.contains('\\')) {
        return Err(WpdError::PathTraversal(format!(
            "unexpected path separator in filename '{trimmed}'"
        )));
    }

    // Strip a single leading '/' or '\' ONLY if allow_separators is true (normal MTP root '/DCIM/...')
    // Wait: reject leading '\' or '/' if followed by traversal, or reject relative '..' anywhere.
    // Note: normal MTP full_path values start with '/DCIM/...'!
    let normalized = if allow_separators {
        trimmed.trim_start_matches('/')
    } else {
        trimmed
    };
    if normalized.starts_with('\\') {
        return Err(WpdError::PathTraversal(format!("backslash root rejected: '{trimmed}'")));
    }
    if normalized.is_empty() {
        return Err(WpdError::PathTraversal(format!(
            "path '{trimmed}' contains no segments"
        )));
    }

    let mut out = Vec::new();
    for seg in normalized.split(['/', '\\']) {
        if seg == ".." || seg == "." || seg.is_empty() {
            return Err(WpdError::PathTraversal(format!(
                "invalid or traversal segment '{seg}' in '{trimmed}'"
            )));
        }
        out.push(sanitize_component(seg)?);
    }
    Ok(out)
}

pub fn safe_relative_copy_path(entry: &WpdObjectEntry, preserve_tree: bool) -> Result<PathBuf, WpdError> {
    // Always validate both full_path (if non-empty) and filename so traversal payloads
    // cannot slip through even in flat mode.
    let filename_segs = validate_raw_path_string(&entry.filename, false)?;
    let leaf_name = filename_segs
        .into_iter()
        .next()
        .ok_or_else(|| WpdError::PathTraversal("missing filename".to_string()))?;

    let path_segs = if !entry.full_path.trim().is_empty() {
        validate_raw_path_string(&entry.full_path, true)?
    } else {
        vec![leaf_name.clone()]
    };

    if preserve_tree {
        let mut rel = PathBuf::new();
        for seg in path_segs {
            rel.push(seg);
        }
        Ok(rel)
    } else {
        Ok(PathBuf::from(leaf_name))
    }
}

fn ensure_safe_parent_dir(canon_dest: &Path, target_path: &Path) -> Result<(), WpdError> {
    let parent = target_path
        .parent()
        .ok_or_else(|| WpdError::PathTraversal("target path has no parent directory".to_string()))?;
    std::fs::create_dir_all(parent)?;
    let canon_parent = std::fs::canonicalize(parent)?;
    if !canon_parent.starts_with(canon_dest) {
        return Err(WpdError::PathTraversal(format!(
            "resolved parent '{}' escapes destination '{}'",
            canon_parent.display(),
            canon_dest.display()
        )));
    }
    Ok(())
}

fn open_unique_output_file(target_path: &Path, overwrite: bool) -> Result<(PathBuf, std::fs::File), WpdError> {
    if overwrite {
        if let Ok(meta) = std::fs::symlink_metadata(target_path)
            && meta.file_type().is_symlink()
        {
            return Err(WpdError::PathTraversal(format!(
                "refusing to overwrite symlink '{}'",
                target_path.display()
            )));
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(target_path)?;
        return Ok((target_path.to_path_buf(), file));
    }

    match OpenOptions::new().write(true).create_new(true).open(target_path) {
        Ok(file) => Ok((target_path.to_path_buf(), file)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
            let stem = target_path
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("file");
            let ext = target_path.extension().and_then(|s| s.to_str());
            for idx in 1..=10_000usize {
                let cand_name = match ext {
                    Some(e) if !e.is_empty() => format!("{stem} ({idx}).{e}"),
                    _ => format!("{stem} ({idx})"),
                };
                let cand_path = parent.join(cand_name);
                match OpenOptions::new().write(true).create_new(true).open(&cand_path) {
                    Ok(f) => return Ok((cand_path, f)),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(err) => return Err(WpdError::Io(err)),
                }
            }
            Err(WpdError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("could not allocate unique filename near '{}'", target_path.display()),
            )))
        }
        Err(e) => Err(WpdError::Io(e)),
    }
}

pub fn copy_out(
    source: &dyn MtpDeviceSource,
    entries: &[WpdObjectEntry],
    dest_dir: &Path,
    opts: &CopyOutOptions,
) -> Result<Vec<CopyOutRecord>, WpdError> {
    std::fs::create_dir_all(dest_dir)?;
    let canon_dest = std::fs::canonicalize(dest_dir)?;

    let mut records = Vec::new();
    for entry in entries {
        if entry.is_folder {
            continue;
        }
        let rel = safe_relative_copy_path(entry, opts.preserve_tree)?;
        let initial_target = canon_dest.join(&rel);
        ensure_safe_parent_dir(&canon_dest, &initial_target)?;

        let (final_path, file) = open_unique_output_file(&initial_target, opts.overwrite)?;
        let mut writer = BufWriter::new(file);
        match source.copy_object_to(&entry.device_id, &entry.object_id, &mut writer, opts.max_copy_bytes) {
            Ok(bytes_written) => {
                records.push(CopyOutRecord {
                    device_id: entry.device_id.clone(),
                    object_id: entry.object_id.clone(),
                    source_path: entry.full_path.clone(),
                    destination_path: final_path,
                    bytes_written,
                });
            }
            Err(err) => {
                drop(writer);
                let _ = std::fs::remove_file(&final_path);
                return Err(err);
            }
        }
    }
    Ok(records)
}
