use std::io::Write;

use crate::error::WpdError;
use crate::model::{WpdDeviceInfo, WpdObjectEntry};

pub trait MtpDeviceSource: Send + Sync {
    fn list_devices(&self) -> Result<Vec<WpdDeviceInfo>, WpdError>;

    fn list_objects(&self, device_id: &str, max_objects: Option<usize>) -> Result<Vec<WpdObjectEntry>, WpdError>;

    fn copy_object_to(
        &self,
        device_id: &str,
        object_id: &str,
        writer: &mut dyn Write,
        max_bytes: Option<u64>,
    ) -> Result<u64, WpdError>;

    fn read_object_bytes(&self, device_id: &str, object_id: &str) -> Result<Vec<u8>, WpdError> {
        let mut buf = Vec::new();
        self.copy_object_to(device_id, object_id, &mut buf, None)?;
        Ok(buf)
    }

    fn delete_object(&self, _device_id: &str, _object_id: &str) -> Result<(), WpdError> {
        Err(WpdError::UnsupportedPlatform)
    }
}

pub fn infer_extension(filename: &str) -> String {
    match filename.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && !ext.contains(['/', '\\']) => {
            ext.to_ascii_lowercase()
        }
        _ => String::new(),
    }
}

pub fn infer_mime_from_extension(ext: &str) -> &'static str {
    match ext.trim().trim_start_matches('.').to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" | "heif" => "image/heic",
        "dng" => "image/x-adobe-dng",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "3gp" => "video/3gpp",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "opus" => "audio/ogg",
        "m4a" | "aac" => "audio/mp4",
        "flac" => "audio/flac",
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "apk" => "application/vnd.android.package-archive",
        "zip" => "application/zip",
        "ab" => "application/x-android-backup",
        "db" | "sqlite" | "sqlite3" => "application/x-sqlite3",
        _ => "application/octet-stream",
    }
}
