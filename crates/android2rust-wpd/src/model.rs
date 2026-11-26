use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WpdStorageInfo {
    pub object_id: String,
    pub name: String,
    pub file_system: String,
    pub capacity_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WpdDeviceInfo {
    pub id: String,
    pub friendly_name: String,
    pub manufacturer: String,
    pub description: String,
    pub storages: Vec<WpdStorageInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WpdObjectEntry {
    pub device_id: String,
    pub device_name: String,
    pub storage_name: String,
    pub object_id: String,
    pub parent_id: String,
    pub full_path: String,
    pub filename: String,
    pub extension: String,
    pub size_bytes: u64,
    pub created_time: Option<DateTime<Utc>>,
    pub modified_time: Option<DateTime<Utc>>,
    pub content_type: String,
    pub is_folder: bool,
    pub can_delete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MobileFileQuery {
    pub device_filter: Option<String>,
    pub storage_filter: Option<String>,
    pub path_prefix: Option<String>,
    pub pattern: Option<String>,
    pub use_regex: bool,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub modified_after: Option<DateTime<Utc>>,
    pub modified_before: Option<DateTime<Utc>>,
    pub content_type: Option<String>,
    pub extension: Option<String>,
    pub include_folders: bool,
    pub max_results: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyOutOptions {
    pub preserve_tree: bool,
    pub overwrite: bool,
    pub max_copy_bytes: Option<u64>,
}

impl Default for CopyOutOptions {
    fn default() -> Self {
        Self {
            preserve_tree: true,
            overwrite: false,
            max_copy_bytes: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyOutRecord {
    pub device_id: String,
    pub object_id: String,
    pub source_path: String,
    pub destination_path: PathBuf,
    pub bytes_written: u64,
}
