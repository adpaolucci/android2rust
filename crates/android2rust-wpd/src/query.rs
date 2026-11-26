use chrono::{DateTime, Utc};
use regex::{Regex, RegexBuilder};

use crate::error::WpdError;
use crate::model::{MobileFileQuery, WpdObjectEntry};
use crate::source::MtpDeviceSource;

#[derive(Debug, Clone)]
enum CompiledPattern {
    Regex { re: Regex, match_full_path: bool },
    GlobSet(Vec<(Regex, bool)>),
}

impl CompiledPattern {
    fn compile(pattern: &str, use_regex: bool) -> Result<Self, WpdError> {
        let trimmed = pattern.trim();
        if use_regex {
            // In regex mode `\` is a regex escape metacharacter (e.g. `\d`, `\.`), not a path separator.
            let match_full_path = trimmed.contains('/');
            let re = RegexBuilder::new(trimmed)
                .case_insensitive(true)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| WpdError::InvalidQuery(format!("invalid regex '{trimmed}': {e}")))?;
            Ok(Self::Regex { re, match_full_path })
        } else {
            let parts: Vec<&str> = trimmed
                .split([';', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                return Err(WpdError::InvalidQuery("empty wildcard pattern".to_string()));
            }
            let mut regexes = Vec::with_capacity(parts.len());
            for part in parts {
                let normalized = part.replace('\\', "/");
                let match_full_path = normalized.contains('/');
                let re = glob_to_regex(&normalized)?;
                regexes.push((re, match_full_path));
            }
            Ok(Self::GlobSet(regexes))
        }
    }

    fn matches_entry(&self, entry: &WpdObjectEntry) -> bool {
        match self {
            Self::Regex { re, match_full_path } => matches_regex_target(re, *match_full_path, entry),
            Self::GlobSet(list) => list
                .iter()
                .any(|(re, match_full_path)| matches_regex_target(re, *match_full_path, entry)),
        }
    }
}

fn matches_regex_target(re: &Regex, match_full_path: bool, entry: &WpdObjectEntry) -> bool {
    if !match_full_path {
        return re.is_match(entry.filename.as_str());
    }
    let target = entry.full_path.as_str();
    if re.is_match(target) {
        return true;
    }
    let normalized = target.replace('\\', "/");
    let stripped = normalized.trim_start_matches('/');
    re.is_match(&normalized) || re.is_match(stripped)
}

fn glob_to_regex(glob: &str) -> Result<Regex, WpdError> {
    let normalized = glob.replace('\\', "/");
    let mut expr = String::with_capacity(normalized.len() * 2 + 4);
    expr.push('^');
    for ch in normalized.chars() {
        match ch {
            '*' => expr.push_str(".*"),
            '?' => expr.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                expr.push('\\');
                expr.push(ch);
            }
            other => expr.push(other),
        }
    }
    expr.push('$');
    RegexBuilder::new(&expr)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| WpdError::InvalidQuery(format!("invalid glob pattern '{glob}': {e}")))
}

impl MobileFileQuery {
    pub fn validate(&self) -> Result<(), WpdError> {
        if let (Some(min), Some(max)) = (self.min_size, self.max_size)
            && min > max
        {
            return Err(WpdError::InvalidQuery(format!(
                "min_size ({min}) cannot exceed max_size ({max})"
            )));
        }
        if let (Some(after), Some(before)) = (self.created_after, self.created_before)
            && after > before
        {
            return Err(WpdError::InvalidQuery(format!(
                "created_after ({after}) cannot be later than created_before ({before})"
            )));
        }
        if let (Some(after), Some(before)) = (self.modified_after, self.modified_before)
            && after > before
        {
            return Err(WpdError::InvalidQuery(format!(
                "modified_after ({after}) cannot be later than modified_before ({before})"
            )));
        }
        if let Some(pat) = self.pattern.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let _ = CompiledPattern::compile(pat, self.use_regex)?;
        }
        Ok(())
    }

    pub fn matches(&self, entry: &WpdObjectEntry) -> Result<bool, WpdError> {
        self.validate()?;
        let compiled = self
            .pattern
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|p| CompiledPattern::compile(p, self.use_regex))
            .transpose()?;
        Ok(self.matches_with_compiled(entry, compiled.as_ref()))
    }

    fn matches_with_compiled(&self, entry: &WpdObjectEntry, compiled: Option<&CompiledPattern>) -> bool {
        if !self.include_folders && entry.is_folder {
            return false;
        }
        if let Some(dev) = self.device_filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let needle = dev.to_ascii_lowercase();
            if !entry.device_name.to_ascii_lowercase().contains(&needle)
                && !entry.device_id.to_ascii_lowercase().contains(&needle)
            {
                return false;
            }
        }
        if let Some(st) = self.storage_filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let needle = st.to_ascii_lowercase();
            if !entry.storage_name.to_ascii_lowercase().contains(&needle) {
                return false;
            }
        }
        if let Some(prefix) = self.path_prefix.as_deref().map(str::trim).filter(|s| !s.is_empty())
            && !matches_path_prefix(&entry.full_path, prefix)
        {
            return false;
        }
        if let Some(pat) = compiled
            && !pat.matches_entry(entry)
        {
            return false;
        }
        if let Some(min) = self.min_size
            && entry.size_bytes < min
        {
            return false;
        }
        if let Some(max) = self.max_size
            && entry.size_bytes > max
        {
            return false;
        }
        if !matches_date_range(entry.created_time, self.created_after, self.created_before) {
            return false;
        }
        if !matches_date_range(entry.modified_time, self.modified_after, self.modified_before) {
            return false;
        }
        if let Some(ext_filter) = self.extension.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let entry_ext = entry.extension.trim_start_matches('.').to_ascii_lowercase();
            let matched = ext_filter
                .split([';', ','])
                .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .any(|want| entry_ext == want);
            if !matched {
                return false;
            }
        }
        if let Some(mime_filter) = self.content_type.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let entry_mime = entry.content_type.to_ascii_lowercase();
            let matched = mime_filter
                .split([';', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .any(|spec| mime_matches(&entry_mime, &spec.to_ascii_lowercase()));
            if !matched {
                return false;
            }
        }
        true
    }
}

fn normalize_mtp_prefix(raw: &str) -> String {
    let replaced = raw.replace('\\', "/");
    let trimmed = replaced.trim().trim_matches('/');
    format!("/{}", trimmed.to_ascii_lowercase())
}

fn matches_path_prefix(full_path: &str, prefix: &str) -> bool {
    let norm_prefix = normalize_mtp_prefix(prefix);
    let norm_path = normalize_mtp_prefix(full_path);
    if norm_prefix == "/" {
        return norm_path.starts_with('/');
    }
    norm_path == norm_prefix
        || norm_path
            .strip_prefix(&norm_prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn matches_date_range(
    value: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
) -> bool {
    if after.is_none() && before.is_none() {
        return true;
    }
    let Some(ts) = value else {
        return false;
    };
    if let Some(min_ts) = after
        && ts < min_ts
    {
        return false;
    }
    if let Some(max_ts) = before
        && ts > max_ts
    {
        return false;
    }
    true
}

fn mime_matches(entry_mime: &str, filter: &str) -> bool {
    if filter == "*/*" || filter == "*" {
        return true;
    }
    if let Some(prefix) = filter.strip_suffix("/*") {
        return entry_mime.split_once('/').is_some_and(|(maj, _)| maj == prefix);
    }
    if let Some(suffix) = filter.strip_prefix("*/") {
        return entry_mime.split_once('/').is_some_and(|(_, min)| min == suffix);
    }
    entry_mime == filter
}

pub fn search_devices(source: &dyn MtpDeviceSource, query: &MobileFileQuery) -> Result<Vec<WpdObjectEntry>, WpdError> {
    query.validate()?;
    let compiled = query
        .pattern
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|p| CompiledPattern::compile(p, query.use_regex))
        .transpose()?;

    let devices = source.list_devices()?;
    if devices.is_empty() {
        return Err(WpdError::NoDevices);
    }
    if query.max_results == Some(0) {
        return Ok(Vec::new());
    }

    let dev_needle = query
        .device_filter
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    let mut results = Vec::new();
    for dev in devices {
        if let Some(needle) = &dev_needle
            && !dev.friendly_name.to_ascii_lowercase().contains(needle)
            && !dev.id.to_ascii_lowercase().contains(needle)
        {
            continue;
        }
        let entries = source.list_objects(&dev.id, None)?;
        for entry in entries {
            if query.matches_with_compiled(&entry, compiled.as_ref()) {
                results.push(entry);
                if let Some(limit) = query.max_results
                    && results.len() >= limit
                {
                    return Ok(results);
                }
            }
        }
    }

    Ok(results)
}
