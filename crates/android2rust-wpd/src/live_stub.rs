use crate::error::WpdError;
use crate::model::{WpdDeviceInfo, WpdObjectEntry};
use crate::source::MtpDeviceSource;
use std::io::Write;

#[derive(Debug, Default, Clone)]
pub struct LiveWpdSource;

impl LiveWpdSource {
    pub fn new() -> Self {
        Self
    }
}

impl MtpDeviceSource for LiveWpdSource {
    fn list_devices(&self) -> Result<Vec<WpdDeviceInfo>, WpdError> {
        Err(WpdError::UnsupportedPlatform)
    }

    fn list_objects(&self, _device_id: &str, _max_objects: Option<usize>) -> Result<Vec<WpdObjectEntry>, WpdError> {
        Err(WpdError::UnsupportedPlatform)
    }

    fn copy_object_to(
        &self,
        _device_id: &str,
        _object_id: &str,
        _writer: &mut dyn Write,
        _max_bytes: Option<u64>,
    ) -> Result<u64, WpdError> {
        Err(WpdError::UnsupportedPlatform)
    }
}
