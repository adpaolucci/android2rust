use crate::model::AndroidJob;
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub updated_at: String,
    pub job: AndroidJob,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunHistoryEntry {
    pub id: String,
    pub timestamp: String,
    pub job_name: String,
    pub source: String,
    pub destination: String,
    pub dry_run: bool,
    pub command_line: String,
    pub exit_code: i32,
    pub exit_label: String,
    pub is_success: bool,
    pub duration_secs: f64,
    pub records_count: u64,
    pub error_count: u64,
    pub bytes_processed: u64,
    pub summary_text: String,
}

#[derive(Debug, Clone)]
pub struct ProfileStore {
    root_dir: PathBuf,
}

impl ProfileStore {
    pub fn default_store() -> Self {
        let root_dir = dirs::config_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("android2rust");
        Self { root_dir }
    }

    pub fn with_dir(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
        }
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn profiles_path(&self) -> PathBuf {
        self.root_dir.join("profiles.json")
    }

    pub fn history_path(&self) -> PathBuf {
        self.root_dir.join("history.json")
    }

    pub fn load_profiles(&self) -> Result<Vec<SavedProfile>> {
        let path = self.profiles_path();
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(path)?;
        let list: Vec<SavedProfile> = serde_json::from_str(&text)?;
        Ok(list)
    }

    pub fn save_profiles(&self, profiles: &[SavedProfile]) -> Result<()> {
        atomic_write_json(&self.profiles_path(), profiles)
    }

    pub fn upsert_profile(&self, name: &str, description: &str, mut job: AndroidJob) -> Result<Vec<SavedProfile>> {
        let clean_name = name.trim();
        job.name = clean_name.to_string();
        job.description = description.trim().to_string();

        let mut list = self.load_profiles().unwrap_or_default();
        let now = Utc::now().to_rfc3339();
        let id = slugify(clean_name);

        if let Some(existing) = list
            .iter_mut()
            .find(|p| p.id.eq_ignore_ascii_case(&id) || p.name.eq_ignore_ascii_case(clean_name))
        {
            existing.name = clean_name.to_string();
            existing.description = description.trim().to_string();
            existing.updated_at = now;
            existing.job = job;
        } else {
            list.push(SavedProfile {
                id,
                name: clean_name.to_string(),
                description: description.trim().to_string(),
                updated_at: now,
                job,
            });
        }
        list.sort_by_key(|a| a.name.to_ascii_lowercase());
        self.save_profiles(&list)?;
        Ok(list)
    }

    pub fn delete_profile(&self, id_or_name: &str) -> Result<(bool, Vec<SavedProfile>)> {
        let mut list = self.load_profiles().unwrap_or_default();
        let before = list.len();
        list.retain(|p| !p.id.eq_ignore_ascii_case(id_or_name) && !p.name.eq_ignore_ascii_case(id_or_name));
        let removed = list.len() != before;
        if removed {
            self.save_profiles(&list)?;
        }
        Ok((removed, list))
    }

    pub fn find_profile(&self, id_or_name: &str) -> Result<Option<SavedProfile>> {
        let list = self.load_profiles()?;
        Ok(list
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(id_or_name) || p.name.eq_ignore_ascii_case(id_or_name)))
    }

    pub fn load_history(&self) -> Result<Vec<RunHistoryEntry>> {
        let path = self.history_path();
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(path)?;
        let list: Vec<RunHistoryEntry> = serde_json::from_str(&text)?;
        Ok(list)
    }

    pub fn append_history(&self, entry: RunHistoryEntry) -> Result<Vec<RunHistoryEntry>> {
        let mut list = self.load_history().unwrap_or_default();
        list.insert(0, entry);
        list.truncate(200);
        atomic_write_json(&self.history_path(), &list)?;
        Ok(list)
    }

    pub fn clear_history(&self) -> Result<()> {
        atomic_write_json(&self.history_path(), &Vec::<RunHistoryEntry>::new())
    }
}

fn slugify(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "profile".to_string()
    } else {
        trimmed
    }
}

fn atomic_write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("data.json");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = path.with_file_name(format!("{fname}.{}.{}.tmp", std::process::id(), nanos));
    std::fs::write(&tmp_path, json)?;
    if std::fs::rename(&tmp_path, path).is_err() {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        if let Err(err) = std::fs::rename(&tmp_path, path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AndroidOperation;
    use tempfile::TempDir;

    #[test]
    fn saves_updates_and_deletes_profiles_atomically() {
        let tmp = TempDir::new().unwrap();
        let store = ProfileStore::with_dir(tmp.path());

        let mut job = AndroidJob {
            operation: AndroidOperation::Pull,
            source_path: "/sdcard/DCIM".to_string(),
            target_path: r"D:\DCIM".to_string(),
            ..Default::default()
        };

        let list = store.upsert_profile("Daily DCIM", "Camera pull", job.clone()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "daily-dcim");

        job.dry_run = true;
        let list = store.upsert_profile("Daily DCIM", "Updated", job).unwrap();
        assert!(list[0].job.dry_run);

        let (removed, list) = store.delete_profile("daily-dcim").unwrap();
        assert!(removed);
        assert!(list.is_empty());
    }
}
