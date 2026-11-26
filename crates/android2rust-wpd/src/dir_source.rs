use chrono::{DateTime, Utc};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::error::WpdError;
use crate::model::{WpdDeviceInfo, WpdObjectEntry, WpdStorageInfo};
use crate::source::{MtpDeviceSource, infer_extension, infer_mime_from_extension};

pub const DEFAULT_MAX_DEPTH: usize = 64;
pub const DEFAULT_MAX_SCAN_ENTRIES: usize = 250_000;

struct StorageTarget<'a> {
    device_id: &'a str,
    device_name: &'a str,
    storage_name: &'a str,
}

#[derive(Debug, Clone)]
pub struct DirectoryMtpSource {
    root: PathBuf,
    device_id: String,
    device_name: String,
    storage_name: String,
    multi_device_tree: bool,
    max_depth: usize,
    max_entries: usize,
}

impl DirectoryMtpSource {
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root_buf = root.as_ref().to_path_buf();
        let label = root_buf
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("Synthetic MTP Device")
            .to_string();
        Self {
            root: root_buf,
            device_id: "dir://synthetic-device-0".to_string(),
            device_name: label,
            storage_name: "Internal shared storage".to_string(),
            multi_device_tree: false,
            max_depth: DEFAULT_MAX_DEPTH,
            max_entries: DEFAULT_MAX_SCAN_ENTRIES,
        }
    }

    pub fn with_labels(
        root: impl AsRef<Path>,
        device_id: impl Into<String>,
        device_name: impl Into<String>,
        storage_name: impl Into<String>,
    ) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            device_id: device_id.into(),
            device_name: device_name.into(),
            storage_name: storage_name.into(),
            multi_device_tree: false,
            max_depth: DEFAULT_MAX_DEPTH,
            max_entries: DEFAULT_MAX_SCAN_ENTRIES,
        }
    }

    /// Interprets `<root>/<DeviceName>/<StorageName>/...` as multiple synthetic devices & storages.
    pub fn multi_device(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            device_id: String::new(),
            device_name: String::new(),
            storage_name: String::new(),
            multi_device_tree: true,
            max_depth: DEFAULT_MAX_DEPTH,
            max_entries: DEFAULT_MAX_SCAN_ENTRIES,
        }
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth.max(1);
        self
    }

    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries.max(1);
        self
    }

    fn ensure_root_exists(&self) -> Result<PathBuf, WpdError> {
        if !self.root.exists() {
            return Err(WpdError::DeviceNotFound(format!(
                "synthetic WPD directory does not exist: {}",
                self.root.display()
            )));
        }
        if !self.root.is_dir() {
            return Err(WpdError::DeviceNotFound(format!(
                "synthetic WPD source is not a directory: {}",
                self.root.display()
            )));
        }
        Ok(std::fs::canonicalize(&self.root)?)
    }

    fn scan_storage_dir(
        &self,
        canon_root: &Path,
        storage_dir: &Path,
        target: StorageTarget<'_>,
        max_objects: Option<usize>,
        out: &mut Vec<WpdObjectEntry>,
    ) -> Result<(), WpdError> {
        let StorageTarget {
            device_id,
            device_name,
            storage_name,
        } = target;
        let cap = max_objects.unwrap_or(self.max_entries).min(self.max_entries);
        let walker = WalkDir::new(storage_dir)
            .follow_links(false)
            .max_depth(self.max_depth)
            .sort_by_file_name();

        for entry_res in walker {
            if out.len() >= cap {
                break;
            }
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.depth() == 0 {
                continue;
            }
            if entry.path_is_symlink() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let rel_from_storage = match entry.path().strip_prefix(storage_dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Ok(canon_entry) = std::fs::canonicalize(entry.path())
                && !canon_entry.starts_with(canon_root)
            {
                continue;
            }

            let rel_slash = path_to_forward_slashes(rel_from_storage);
            if rel_slash.is_empty() {
                continue;
            }
            let full_path = format!("/{rel_slash}");
            let object_id = if self.multi_device_tree {
                format!("{storage_name}/{rel_slash}")
            } else {
                rel_slash.clone()
            };
            let parent_rel = rel_from_storage
                .parent()
                .map(path_to_forward_slashes)
                .unwrap_or_default();
            let parent_id = if parent_rel.is_empty() {
                "DEVICE".to_string()
            } else if self.multi_device_tree {
                format!("{storage_name}/{parent_rel}")
            } else {
                parent_rel
            };
            let filename = entry.file_name().to_string_lossy().to_string();
            let is_folder = meta.is_dir();
            let extension = if is_folder {
                String::new()
            } else {
                infer_extension(&filename)
            };
            let content_type = if is_folder {
                "inode/directory".to_string()
            } else {
                infer_mime_from_extension(&extension).to_string()
            };
            let size_bytes = if is_folder { 0 } else { meta.len() };
            let created_time = meta.created().ok().map(DateTime::<Utc>::from);
            let modified_time = meta.modified().ok().map(DateTime::<Utc>::from);

            out.push(WpdObjectEntry {
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                storage_name: storage_name.to_string(),
                object_id,
                parent_id,
                full_path,
                filename,
                extension,
                size_bytes,
                created_time,
                modified_time,
                content_type,
                is_folder,
                can_delete: false,
            });
        }
        Ok(())
    }
}

impl MtpDeviceSource for DirectoryMtpSource {
    fn list_devices(&self) -> Result<Vec<WpdDeviceInfo>, WpdError> {
        let _canon = self.ensure_root_exists()?;
        if !self.multi_device_tree {
            return Ok(vec![WpdDeviceInfo {
                id: self.device_id.clone(),
                friendly_name: self.device_name.clone(),
                manufacturer: "Android2Rust Synthetic Fixture".to_string(),
                description: format!("Directory fixture at {}", self.root.display()),
                storages: vec![WpdStorageInfo {
                    object_id: "STORAGE-0".to_string(),
                    name: self.storage_name.clone(),
                    file_system: "SyntheticFS".to_string(),
                    capacity_bytes: None,
                    free_bytes: None,
                }],
            }]);
        }

        let mut devices = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(&self.root)?.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        for dev_entry in entries {
            let Ok(ft) = dev_entry.file_type() else {
                continue;
            };
            if ft.is_symlink() || !ft.is_dir() {
                continue;
            }
            let dev_name = dev_entry.file_name().to_string_lossy().to_string();
            let dev_id = format!("dir://{dev_name}");
            let mut storages = Vec::new();
            if let Ok(st_entries) = std::fs::read_dir(dev_entry.path()) {
                let mut sorted_st: Vec<_> = st_entries.filter_map(Result::ok).collect();
                sorted_st.sort_by_key(|e| e.file_name());
                for (idx, st) in sorted_st.into_iter().enumerate() {
                    if let Ok(sft) = st.file_type()
                        && !sft.is_symlink()
                        && sft.is_dir()
                    {
                        storages.push(WpdStorageInfo {
                            object_id: format!("STORAGE-{idx}"),
                            name: st.file_name().to_string_lossy().to_string(),
                            file_system: "SyntheticFS".to_string(),
                            capacity_bytes: None,
                            free_bytes: None,
                        });
                    }
                }
            }
            devices.push(WpdDeviceInfo {
                id: dev_id,
                friendly_name: dev_name,
                manufacturer: "Android2Rust Synthetic Fixture".to_string(),
                description: format!("Directory fixture under {}", dev_entry.path().display()),
                storages,
            });
        }

        if devices.is_empty() {
            return Err(WpdError::NoDevices);
        }
        Ok(devices)
    }

    fn list_objects(&self, device_id: &str, max_objects: Option<usize>) -> Result<Vec<WpdObjectEntry>, WpdError> {
        let canon_root = self.ensure_root_exists()?;
        if !self.multi_device_tree {
            if device_id != self.device_id {
                return Err(WpdError::DeviceNotFound(device_id.to_string()));
            }
            let mut out = Vec::new();
            self.scan_storage_dir(
                &canon_root,
                &self.root,
                StorageTarget {
                    device_id: &self.device_id,
                    device_name: &self.device_name,
                    storage_name: &self.storage_name,
                },
                max_objects,
                &mut out,
            )?;
            return Ok(out);
        }

        let devices = self.list_devices()?;
        let Some(dev) = devices.into_iter().find(|d| d.id == device_id) else {
            return Err(WpdError::DeviceNotFound(device_id.to_string()));
        };
        let dev_dir = self.root.join(&dev.friendly_name);
        let mut out = Vec::new();
        for storage in &dev.storages {
            let st_dir = dev_dir.join(&storage.name);
            let remaining = max_objects.map(|m| m.saturating_sub(out.len()));
            if remaining == Some(0) {
                break;
            }
            self.scan_storage_dir(
                &canon_root,
                &st_dir,
                StorageTarget {
                    device_id: &dev.id,
                    device_name: &dev.friendly_name,
                    storage_name: &storage.name,
                },
                remaining,
                &mut out,
            )?;
        }
        Ok(out)
    }

    fn copy_object_to(
        &self,
        device_id: &str,
        object_id: &str,
        writer: &mut dyn Write,
        max_bytes: Option<u64>,
    ) -> Result<u64, WpdError> {
        let canon_root = self.ensure_root_exists()?;
        let candidate = if !self.multi_device_tree {
            if device_id != self.device_id {
                return Err(WpdError::DeviceNotFound(device_id.to_string()));
            }
            let mut p = self.root.clone();
            for seg in object_id.split(['/', '\\']) {
                if seg.is_empty() || seg == "." || seg == ".." {
                    return Err(WpdError::PathTraversal(object_id.to_string()));
                }
                p.push(seg);
            }
            p
        } else {
            let dev_name = device_id
                .strip_prefix("dir://")
                .ok_or_else(|| WpdError::DeviceNotFound(device_id.to_string()))?;
            let mut p = self.root.join(dev_name);
            for seg in object_id.split(['/', '\\']) {
                if seg.is_empty() || seg == "." || seg == ".." {
                    return Err(WpdError::PathTraversal(object_id.to_string()));
                }
                p.push(seg);
            }
            p
        };

        if !candidate.exists() {
            return Err(WpdError::ObjectNotFound {
                device_id: device_id.to_string(),
                object_id: object_id.to_string(),
            });
        }
        let canon_file = std::fs::canonicalize(&candidate)?;
        if !canon_file.starts_with(&canon_root) {
            return Err(WpdError::PathTraversal(object_id.to_string()));
        }

        let mut file = File::open(&canon_file)?;
        let mut buf = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let next_total = total.saturating_add(n as u64);
            if let Some(cap) = max_bytes
                && next_total > cap
            {
                return Err(WpdError::InvalidQuery(format!(
                    "object '{object_id}' exceeds max_copy_bytes limit ({cap} bytes)"
                )));
            }
            writer.write_all(&buf[..n])?;
            total = next_total;
        }
        writer.flush()?;
        Ok(total)
    }
}

fn path_to_forward_slashes(p: &Path) -> String {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(os) => Some(os.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}
