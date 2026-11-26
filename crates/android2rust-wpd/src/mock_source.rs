use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::error::WpdError;
use crate::model::{WpdDeviceInfo, WpdObjectEntry};
use crate::source::MtpDeviceSource;

#[derive(Debug, Clone)]
pub enum MockErrorKind {
    NoDevices,
    AccessDenied(String),
    UnsupportedPlatform,
    ComError(String),
}

impl MockErrorKind {
    fn to_wpd_error(&self) -> WpdError {
        match self {
            Self::NoDevices => WpdError::NoDevices,
            Self::AccessDenied(msg) => WpdError::AccessDenied(msg.clone()),
            Self::UnsupportedPlatform => WpdError::UnsupportedPlatform,
            Self::ComError(msg) => WpdError::ComError(msg.clone()),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct MockState {
    devices: Vec<WpdDeviceInfo>,
    objects: HashMap<String, Vec<WpdObjectEntry>>,
    payloads: HashMap<(String, String), Vec<u8>>,
    injected_list_error: Option<MockErrorKind>,
    injected_read_error: Option<MockErrorKind>,
}

#[derive(Debug, Default, Clone)]
pub struct MockWpdSource {
    state: Arc<Mutex<MockState>>,
}

impl MockWpdSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_device(self, device: WpdDeviceInfo) -> Self {
        self.add_device(device);
        self
    }

    pub fn add_device(&self, device: WpdDeviceInfo) {
        let mut st = self.state.lock().expect("mock lock poisoned");
        st.objects.entry(device.id.clone()).or_default();
        st.devices.push(device);
    }

    pub fn add_entry(&self, entry: WpdObjectEntry, payload: Vec<u8>) {
        let mut st = self.state.lock().expect("mock lock poisoned");
        let dev_id = entry.device_id.clone();
        let obj_id = entry.object_id.clone();
        st.objects.entry(dev_id.clone()).or_default().push(entry);
        st.payloads.insert((dev_id, obj_id), payload);
    }

    pub fn set_list_error(&self, err: Option<MockErrorKind>) {
        let mut st = self.state.lock().expect("mock lock poisoned");
        st.injected_list_error = err;
    }

    pub fn set_read_error(&self, err: Option<MockErrorKind>) {
        let mut st = self.state.lock().expect("mock lock poisoned");
        st.injected_read_error = err;
    }
}

impl MtpDeviceSource for MockWpdSource {
    fn list_devices(&self) -> Result<Vec<WpdDeviceInfo>, WpdError> {
        let st = self.state.lock().expect("mock lock poisoned");
        if let Some(err) = &st.injected_list_error {
            return Err(err.to_wpd_error());
        }
        Ok(st.devices.clone())
    }

    fn list_objects(&self, device_id: &str, max_objects: Option<usize>) -> Result<Vec<WpdObjectEntry>, WpdError> {
        let st = self.state.lock().expect("mock lock poisoned");
        if let Some(err) = &st.injected_list_error {
            return Err(err.to_wpd_error());
        }
        let Some(entries) = st.objects.get(device_id) else {
            return Err(WpdError::DeviceNotFound(device_id.to_string()));
        };
        let mut out = entries.clone();
        if let Some(max) = max_objects {
            out.truncate(max);
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
        let st = self.state.lock().expect("mock lock poisoned");
        if let Some(err) = &st.injected_read_error {
            return Err(err.to_wpd_error());
        }
        let Some(bytes) = st.payloads.get(&(device_id.to_string(), object_id.to_string())) else {
            return Err(WpdError::ObjectNotFound {
                device_id: device_id.to_string(),
                object_id: object_id.to_string(),
            });
        };
        if let Some(cap) = max_bytes
            && (bytes.len() as u64) > cap
        {
            return Err(WpdError::InvalidQuery(format!(
                "object '{object_id}' ({} bytes) exceeds max_copy_bytes limit ({cap})",
                bytes.len()
            )));
        }
        writer.write_all(bytes)?;
        writer.flush()?;
        Ok(bytes.len() as u64)
    }

    fn delete_object(&self, device_id: &str, object_id: &str) -> Result<(), WpdError> {
        let mut st = self.state.lock().expect("mock lock poisoned");
        if let Some(err) = &st.injected_read_error {
            return Err(err.to_wpd_error());
        }
        let Some(entries) = st.objects.get_mut(device_id) else {
            return Err(WpdError::DeviceNotFound(device_id.to_string()));
        };
        let Some(pos) = entries.iter().position(|e| e.object_id == object_id) else {
            return Err(WpdError::ObjectNotFound {
                device_id: device_id.to_string(),
                object_id: object_id.to_string(),
            });
        };
        if !entries[pos].can_delete {
            return Err(WpdError::AccessDenied(format!(
                "object '{object_id}' on '{device_id}' is marked non-deletable"
            )));
        }
        entries.remove(pos);
        st.payloads.remove(&(device_id.to_string(), object_id.to_string()));
        Ok(())
    }
}
