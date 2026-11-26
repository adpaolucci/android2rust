use std::collections::{HashSet, VecDeque};
use std::ffi::c_void;
use std::io::Write;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use windows::Win32::Devices::PortableDevices::{
    IEnumPortableDeviceObjectIDs, IPortableDevice, IPortableDeviceContent, IPortableDeviceKeyCollection,
    IPortableDeviceManager, IPortableDevicePropVariantCollection, IPortableDeviceProperties, IPortableDeviceValues,
    PORTABLE_DEVICE_DELETE_NO_RECURSION, PortableDevice, PortableDeviceKeyCollection, PortableDeviceManager,
    PortableDevicePropVariantCollection, PortableDeviceValues, WPD_CLIENT_DESIRED_ACCESS, WPD_CLIENT_MAJOR_VERSION,
    WPD_CLIENT_MINOR_VERSION, WPD_CLIENT_NAME, WPD_CLIENT_REVISION, WPD_CONTENT_TYPE_AUDIO, WPD_CONTENT_TYPE_DOCUMENT,
    WPD_CONTENT_TYPE_FOLDER, WPD_CONTENT_TYPE_FUNCTIONAL_OBJECT, WPD_CONTENT_TYPE_IMAGE, WPD_CONTENT_TYPE_VIDEO,
    WPD_DEVICE_OBJECT_ID, WPD_FUNCTIONAL_CATEGORY_STORAGE, WPD_FUNCTIONAL_OBJECT_CATEGORY, WPD_OBJECT_CAN_DELETE,
    WPD_OBJECT_CONTENT_TYPE, WPD_OBJECT_DATE_CREATED, WPD_OBJECT_DATE_MODIFIED, WPD_OBJECT_NAME,
    WPD_OBJECT_ORIGINAL_FILE_NAME, WPD_OBJECT_PARENT_ID, WPD_OBJECT_SIZE, WPD_RESOURCE_DEFAULT, WPD_STORAGE_CAPACITY,
    WPD_STORAGE_FILE_SYSTEM_TYPE, WPD_STORAGE_FREE_SPACE_IN_BYTES,
};
use windows::Win32::Foundation::{E_ACCESSDENIED, PROPERTYKEY, RPC_E_CHANGED_MODE, S_FALSE, S_OK, SYSTEMTIME};
use windows::Win32::System::Com::StructuredStorage::{PROPVARIANT, PropVariantClear};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
    STGM_READ,
};
use windows::Win32::System::Variant::{
    VT_BOOL, VT_BSTR, VT_DATE, VT_FILETIME, VT_I4, VT_I8, VT_LPWSTR, VT_UI4, VT_UI8, VariantTimeToSystemTime,
};
use windows::core::{GUID, HRESULT, HSTRING, PCWSTR, PWSTR};

use crate::error::WpdError;
use crate::model::{WpdDeviceInfo, WpdObjectEntry, WpdStorageInfo};
use crate::source::{MtpDeviceSource, infer_extension, infer_mime_from_extension};

const MAX_TRAVERSAL_DEPTH: usize = 64;
const GENERIC_READ_ACCESS: u32 = 0x8000_0000;
const GENERIC_READ_WRITE_ACCESS: u32 = 0xC000_0000;

#[derive(Debug, Default, Clone)]
pub struct LiveWpdSource;

impl LiveWpdSource {
    pub fn new() -> Self {
        Self
    }
}

struct ComGuard {
    should_uninit: bool,
}

impl ComGuard {
    fn init_mta() -> Result<Self, WpdError> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr == S_OK || hr == S_FALSE {
            Ok(Self { should_uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            Ok(Self { should_uninit: false })
        } else {
            Err(WpdError::ComError(format!(
                "CoInitializeEx failed: 0x{:08X}",
                hr.0 as u32
            )))
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

struct CoTaskMemPwstr(PWSTR);

impl CoTaskMemPwstr {
    fn into_string(self) -> String {
        if self.0.is_null() {
            String::new()
        } else {
            unsafe { self.0.to_string().unwrap_or_default() }
        }
    }
}

impl Drop for CoTaskMemPwstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CoTaskMemFree(Some(self.0.0 as *const c_void));
            }
            self.0 = PWSTR::null();
        }
    }
}

struct CoTaskMemPwstrVec(Vec<PWSTR>);

impl CoTaskMemPwstrVec {
    fn new(len: usize) -> Self {
        Self(vec![PWSTR::null(); len])
    }
}

impl Drop for CoTaskMemPwstrVec {
    fn drop(&mut self) {
        for ptr in &mut self.0 {
            if !ptr.is_null() {
                unsafe {
                    CoTaskMemFree(Some(ptr.0 as *const c_void));
                }
                *ptr = PWSTR::null();
            }
        }
    }
}

struct PropVariantGuard(PROPVARIANT);

impl Drop for PropVariantGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = PropVariantClear(&mut self.0);
        }
    }
}

struct OpenDeviceGuard {
    device: IPortableDevice,
}

impl OpenDeviceGuard {
    fn open(pnp_device_id: &str, writable: bool) -> Result<Self, WpdError> {
        let device: IPortableDevice =
            unsafe { CoCreateInstance(&PortableDevice, None, CLSCTX_INPROC_SERVER) }.map_err(map_win_err)?;
        let client_info: IPortableDeviceValues =
            unsafe { CoCreateInstance(&PortableDeviceValues, None, CLSCTX_INPROC_SERVER) }.map_err(map_win_err)?;

        let app_name = HSTRING::from("android2rust-wpd");
        unsafe {
            client_info
                .SetStringValue(&WPD_CLIENT_NAME, &app_name)
                .map_err(map_win_err)?;
            client_info
                .SetUnsignedIntegerValue(&WPD_CLIENT_MAJOR_VERSION, 1)
                .map_err(map_win_err)?;
            client_info
                .SetUnsignedIntegerValue(&WPD_CLIENT_MINOR_VERSION, 0)
                .map_err(map_win_err)?;
            client_info
                .SetUnsignedIntegerValue(&WPD_CLIENT_REVISION, 0)
                .map_err(map_win_err)?;
            client_info
                .SetUnsignedIntegerValue(
                    &WPD_CLIENT_DESIRED_ACCESS,
                    if writable {
                        GENERIC_READ_WRITE_ACCESS
                    } else {
                        GENERIC_READ_ACCESS
                    },
                )
                .map_err(map_win_err)?;
        }

        let dev_hstr = HSTRING::from(pnp_device_id);
        unsafe { device.Open(&dev_hstr, &client_info) }.map_err(map_win_err)?;
        Ok(Self { device })
    }

    fn content(&self) -> Result<IPortableDeviceContent, WpdError> {
        unsafe { self.device.Content() }.map_err(map_win_err)
    }
}

impl Drop for OpenDeviceGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = self.device.Close();
        }
    }
}

fn map_win_err(err: windows::core::Error) -> WpdError {
    let code = err.code();
    if code == E_ACCESSDENIED {
        WpdError::AccessDenied(err.message())
    } else if code == HRESULT(0x8007_0002u32 as i32) || code == HRESULT(0x8007_0490u32 as i32) {
        WpdError::DeviceNotFound(err.message())
    } else {
        WpdError::ComError(format!("0x{:08X}: {}", code.0 as u32, err.message()))
    }
}

fn read_manager_string(
    mgr: &IPortableDeviceManager,
    dev_id: &HSTRING,
    getter: unsafe fn(&IPortableDeviceManager, PCWSTR, PWSTR, *mut u32) -> windows::core::Result<()>,
) -> String {
    let mut len: u32 = 0;
    let res = unsafe { getter(mgr, PCWSTR(dev_id.as_ptr()), PWSTR::null(), &mut len) };
    if res.is_err() || len == 0 {
        return String::new();
    }
    let mut buf: Vec<u16> = vec![0u16; len as usize];
    if unsafe { getter(mgr, PCWSTR(dev_id.as_ptr()), PWSTR(buf.as_mut_ptr()), &mut len) }.is_err() {
        return String::new();
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn enum_child_ids(content: &IPortableDeviceContent, parent_id: &str) -> Result<Vec<String>, WpdError> {
    let parent_h = HSTRING::from(parent_id);
    let enum_ids: IEnumPortableDeviceObjectIDs =
        unsafe { content.EnumObjects(0, &parent_h, None) }.map_err(map_win_err)?;

    let mut out = Vec::new();
    loop {
        let mut batch = CoTaskMemPwstrVec::new(64);
        let mut fetched: u32 = 0;
        let hr = unsafe { enum_ids.Next(&mut batch.0, &mut fetched) };
        if hr.is_err() {
            return Err(map_win_err(windows::core::Error::from(hr)));
        }
        if fetched == 0 {
            break;
        }
        for ptr in batch.0.iter().take(fetched as usize) {
            if !ptr.is_null() {
                let s = unsafe { ptr.to_string().unwrap_or_default() };
                if !s.is_empty() {
                    out.push(s);
                }
            }
        }
        if hr == S_FALSE {
            break;
        }
    }
    Ok(out)
}

fn build_object_keys() -> Result<IPortableDeviceKeyCollection, WpdError> {
    let keys: IPortableDeviceKeyCollection =
        unsafe { CoCreateInstance(&PortableDeviceKeyCollection, None, CLSCTX_INPROC_SERVER) }.map_err(map_win_err)?;
    for key in [
        &WPD_OBJECT_NAME,
        &WPD_OBJECT_ORIGINAL_FILE_NAME,
        &WPD_OBJECT_CONTENT_TYPE,
        &WPD_OBJECT_SIZE,
        &WPD_OBJECT_DATE_CREATED,
        &WPD_OBJECT_DATE_MODIFIED,
        &WPD_OBJECT_PARENT_ID,
        &WPD_OBJECT_CAN_DELETE,
        &WPD_FUNCTIONAL_OBJECT_CATEGORY,
        &WPD_STORAGE_FILE_SYSTEM_TYPE,
        &WPD_STORAGE_CAPACITY,
        &WPD_STORAGE_FREE_SPACE_IN_BYTES,
    ] {
        unsafe { keys.Add(key) }.map_err(map_win_err)?;
    }
    Ok(keys)
}

fn get_opt_string(vals: &IPortableDeviceValues, key: &PROPERTYKEY) -> Option<String> {
    let pwstr = unsafe { vals.GetStringValue(key) }.ok()?;
    let guard = CoTaskMemPwstr(pwstr);
    let s = guard.into_string();
    if s.is_empty() { None } else { Some(s) }
}

fn get_opt_u64(vals: &IPortableDeviceValues, key: &PROPERTYKEY) -> Option<u64> {
    if let Ok(v) = unsafe { vals.GetUnsignedLargeIntegerValue(key) } {
        return Some(v);
    }
    let pv = PropVariantGuard(unsafe { vals.GetValue(key) }.ok()?);
    unsafe {
        let vt = pv.0.Anonymous.Anonymous.vt;
        if vt == VT_UI8 {
            Some(pv.0.Anonymous.Anonymous.Anonymous.uhVal)
        } else if vt == VT_UI4 {
            Some(u64::from(pv.0.Anonymous.Anonymous.Anonymous.ulVal))
        } else if vt == VT_I8 {
            u64::try_from(pv.0.Anonymous.Anonymous.Anonymous.hVal).ok()
        } else if vt == VT_I4 {
            u64::try_from(pv.0.Anonymous.Anonymous.Anonymous.lVal).ok()
        } else {
            None
        }
    }
}

fn get_opt_guid(vals: &IPortableDeviceValues, key: &PROPERTYKEY) -> Option<GUID> {
    unsafe { vals.GetGuidValue(key) }.ok()
}

fn get_opt_bool(vals: &IPortableDeviceValues, key: &PROPERTYKEY) -> Option<bool> {
    let pv = PropVariantGuard(unsafe { vals.GetValue(key) }.ok()?);
    unsafe {
        let vt = pv.0.Anonymous.Anonymous.vt;
        if vt == VT_BOOL {
            Some(pv.0.Anonymous.Anonymous.Anonymous.boolVal.as_bool())
        } else {
            None
        }
    }
}

fn get_opt_datetime(vals: &IPortableDeviceValues, key: &PROPERTYKEY) -> Option<DateTime<Utc>> {
    let pv = PropVariantGuard(unsafe { vals.GetValue(key) }.ok()?);
    unsafe {
        let vt = pv.0.Anonymous.Anonymous.vt;
        if vt == VT_DATE {
            let mut st = SYSTEMTIME::default();
            if VariantTimeToSystemTime(pv.0.Anonymous.Anonymous.Anonymous.date, &mut st) != 0 {
                return systemtime_to_utc(&st);
            }
        } else if vt == VT_FILETIME {
            let ft = pv.0.Anonymous.Anonymous.Anonymous.filetime;
            let raw = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
            // Windows FILETIME epoch: 1601-01-01, 100ns ticks; Unix epoch offset = 11644473600s
            const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
            if raw >= UNIX_EPOCH_TICKS {
                let delta = raw - UNIX_EPOCH_TICKS;
                let secs = (delta / 10_000_000) as i64;
                let nanos = ((delta % 10_000_000) * 100) as u32;
                return Utc.timestamp_opt(secs, nanos).single();
            }
        } else if vt == VT_LPWSTR {
            let p = pv.0.Anonymous.Anonymous.Anonymous.pwszVal;
            if !p.is_null() {
                let s = p.to_string().unwrap_or_default();
                return parse_wpd_datetime_str(&s);
            }
        } else if vt == VT_BSTR {
            let b = &pv.0.Anonymous.Anonymous.Anonymous.bstrVal;
            return parse_wpd_datetime_str(&b.to_string());
        }
    }
    None
}

fn systemtime_to_utc(st: &SYSTEMTIME) -> Option<DateTime<Utc>> {
    let date = NaiveDate::from_ymd_opt(i32::from(st.wYear), u32::from(st.wMonth), u32::from(st.wDay))?;
    let ndt = date.and_hms_milli_opt(
        u32::from(st.wHour),
        u32::from(st.wMinute),
        u32::from(st.wSecond),
        u32::from(st.wMilliseconds),
    )?;
    Some(ndt.and_utc())
}

fn parse_wpd_datetime_str(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y/%m/%d:%H:%M:%S%.f",
        "%Y/%m/%d:%H:%M:%S",
        "%Y%m%dT%H%M%S%.f",
        "%Y%m%dT%H%M%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

fn map_wpd_content_type(guid: Option<GUID>, filename: &str, is_folder: bool) -> String {
    if is_folder {
        return "inode/directory".to_string();
    }
    let ext = infer_extension(filename);
    if !ext.is_empty() {
        let inferred = infer_mime_from_extension(&ext);
        if inferred != "application/octet-stream" {
            return inferred.to_string();
        }
    }
    match guid {
        Some(g) if g == WPD_CONTENT_TYPE_IMAGE => "image/*".to_string(),
        Some(g) if g == WPD_CONTENT_TYPE_VIDEO => "video/*".to_string(),
        Some(g) if g == WPD_CONTENT_TYPE_AUDIO => "audio/*".to_string(),
        Some(g) if g == WPD_CONTENT_TYPE_DOCUMENT => "application/octet-stream".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

impl MtpDeviceSource for LiveWpdSource {
    fn list_devices(&self) -> Result<Vec<WpdDeviceInfo>, WpdError> {
        let _com = ComGuard::init_mta()?;
        let mgr: IPortableDeviceManager =
            unsafe { CoCreateInstance(&PortableDeviceManager, None, CLSCTX_INPROC_SERVER) }.map_err(map_win_err)?;
        let _ = unsafe { mgr.RefreshDeviceList() };

        let mut count: u32 = 0;
        unsafe { mgr.GetDevices(std::ptr::null_mut(), &mut count) }.map_err(map_win_err)?;
        if count == 0 {
            return Ok(Vec::new());
        }

        let mut ids = CoTaskMemPwstrVec::new(count as usize);
        unsafe { mgr.GetDevices(ids.0.as_mut_ptr(), &mut count) }.map_err(map_win_err)?;

        let mut devices = Vec::with_capacity(count as usize);
        for ptr in ids.0.iter().take(count as usize) {
            if ptr.is_null() {
                continue;
            }
            let id_str = unsafe { ptr.to_string().unwrap_or_default() };
            if id_str.is_empty() {
                continue;
            }
            let dev_h = HSTRING::from(id_str.as_str());
            let friendly_name = read_manager_string(&mgr, &dev_h, IPortableDeviceManager::GetDeviceFriendlyName);
            let manufacturer = read_manager_string(&mgr, &dev_h, IPortableDeviceManager::GetDeviceManufacturer);
            let description = read_manager_string(&mgr, &dev_h, IPortableDeviceManager::GetDeviceDescription);

            let mut storages = Vec::new();
            if let Ok(guard) = OpenDeviceGuard::open(&id_str, false)
                && let Ok(content) = guard.content()
                && let Ok(props) = unsafe { content.Properties() }
                && let Ok(keys) = build_object_keys()
                && let Ok(top_ids) = enum_child_ids(&content, "DEVICE")
            {
                for child_id in top_ids {
                    let child_h = HSTRING::from(child_id.as_str());
                    if let Ok(vals) = unsafe { props.GetValues(&child_h, &keys) } {
                        let cat = get_opt_guid(&vals, &WPD_FUNCTIONAL_OBJECT_CATEGORY);
                        if cat == Some(WPD_FUNCTIONAL_CATEGORY_STORAGE) {
                            let name = get_opt_string(&vals, &WPD_OBJECT_NAME).unwrap_or_else(|| child_id.clone());
                            let fs = get_opt_string(&vals, &WPD_STORAGE_FILE_SYSTEM_TYPE).unwrap_or_default();
                            let cap = get_opt_u64(&vals, &WPD_STORAGE_CAPACITY);
                            let free = get_opt_u64(&vals, &WPD_STORAGE_FREE_SPACE_IN_BYTES);
                            storages.push(WpdStorageInfo {
                                object_id: child_id,
                                name,
                                file_system: fs,
                                capacity_bytes: cap,
                                free_bytes: free,
                            });
                        }
                    }
                }
            }

            devices.push(WpdDeviceInfo {
                id: id_str.clone(),
                friendly_name: if friendly_name.is_empty() {
                    id_str
                } else {
                    friendly_name
                },
                manufacturer,
                description,
                storages,
            });
        }
        Ok(devices)
    }

    fn list_objects(&self, device_id: &str, max_objects: Option<usize>) -> Result<Vec<WpdObjectEntry>, WpdError> {
        let _com = ComGuard::init_mta()?;
        let mgr: IPortableDeviceManager =
            unsafe { CoCreateInstance(&PortableDeviceManager, None, CLSCTX_INPROC_SERVER) }.map_err(map_win_err)?;
        let dev_h = HSTRING::from(device_id);
        let friendly = read_manager_string(&mgr, &dev_h, IPortableDeviceManager::GetDeviceFriendlyName);
        let device_name = if friendly.is_empty() {
            device_id.to_string()
        } else {
            friendly
        };

        let guard = OpenDeviceGuard::open(device_id, false)?;
        let content = guard.content()?;
        let props: IPortableDeviceProperties = unsafe { content.Properties() }.map_err(map_win_err)?;
        let keys = build_object_keys()?;

        let root_id = unsafe {
            WPD_DEVICE_OBJECT_ID
                .to_string()
                .unwrap_or_else(|_| "DEVICE".to_string())
        };
        let mut queue: VecDeque<(String, String, String, usize)> = VecDeque::new();
        queue.push_back((root_id.clone(), String::new(), String::new(), 0));
        let mut visited = HashSet::new();
        visited.insert(root_id);

        let mut results = Vec::new();
        while let Some((parent_id, storage_name, parent_rel_path, depth)) = queue.pop_front() {
            if depth >= MAX_TRAVERSAL_DEPTH {
                continue;
            }
            let children = match enum_child_ids(&content, &parent_id) {
                Ok(c) => c,
                Err(WpdError::AccessDenied(_)) => continue,
                Err(e) => return Err(e),
            };
            for obj_id in children {
                if !visited.insert(obj_id.clone()) {
                    continue;
                }
                let obj_h = HSTRING::from(obj_id.as_str());
                let Ok(vals) = (unsafe { props.GetValues(&obj_h, &keys) }) else {
                    continue;
                };

                let content_guid = get_opt_guid(&vals, &WPD_OBJECT_CONTENT_TYPE);
                let func_cat = get_opt_guid(&vals, &WPD_FUNCTIONAL_OBJECT_CATEGORY);
                let is_storage = content_guid == Some(WPD_CONTENT_TYPE_FUNCTIONAL_OBJECT)
                    && func_cat == Some(WPD_FUNCTIONAL_CATEGORY_STORAGE);
                let is_folder = is_storage || content_guid == Some(WPD_CONTENT_TYPE_FOLDER);

                let filename = get_opt_string(&vals, &WPD_OBJECT_ORIGINAL_FILE_NAME)
                    .or_else(|| get_opt_string(&vals, &WPD_OBJECT_NAME))
                    .unwrap_or_else(|| obj_id.clone());

                if is_storage {
                    queue.push_back((obj_id, filename, String::new(), depth + 1));
                    continue;
                }

                let cur_storage = if storage_name.is_empty() {
                    "Internal storage".to_string()
                } else {
                    storage_name.clone()
                };
                let full_path = if parent_rel_path.is_empty() {
                    format!("/{filename}")
                } else {
                    format!("{parent_rel_path}/{filename}")
                };

                if is_folder {
                    queue.push_back((obj_id.clone(), cur_storage.clone(), full_path.clone(), depth + 1));
                }

                let extension = if is_folder {
                    String::new()
                } else {
                    infer_extension(&filename)
                };
                let size_bytes = if is_folder {
                    0
                } else {
                    get_opt_u64(&vals, &WPD_OBJECT_SIZE).unwrap_or(0)
                };
                let created_time = get_opt_datetime(&vals, &WPD_OBJECT_DATE_CREATED);
                let modified_time = get_opt_datetime(&vals, &WPD_OBJECT_DATE_MODIFIED);
                let can_delete = get_opt_bool(&vals, &WPD_OBJECT_CAN_DELETE).unwrap_or(false);
                let content_type = map_wpd_content_type(content_guid, &filename, is_folder);

                results.push(WpdObjectEntry {
                    device_id: device_id.to_string(),
                    device_name: device_name.clone(),
                    storage_name: cur_storage,
                    object_id: obj_id,
                    parent_id: parent_id.clone(),
                    full_path,
                    filename,
                    extension,
                    size_bytes,
                    created_time,
                    modified_time,
                    content_type,
                    is_folder,
                    can_delete,
                });

                if let Some(cap) = max_objects
                    && results.len() >= cap
                {
                    return Ok(results);
                }
            }
        }
        Ok(results)
    }

    fn copy_object_to(
        &self,
        device_id: &str,
        object_id: &str,
        writer: &mut dyn Write,
        max_bytes: Option<u64>,
    ) -> Result<u64, WpdError> {
        let _com = ComGuard::init_mta()?;
        let guard = OpenDeviceGuard::open(device_id, false)?;
        let content = guard.content()?;
        let resources = unsafe { content.Transfer() }.map_err(map_win_err)?;

        let obj_h = HSTRING::from(object_id);
        let mut opt_buf_size: u32 = 0;
        let mut stream_opt = None;
        unsafe {
            resources.GetStream(
                &obj_h,
                &WPD_RESOURCE_DEFAULT,
                STGM_READ.0,
                &mut opt_buf_size,
                &mut stream_opt,
            )
        }
        .map_err(map_win_err)?;

        let stream = stream_opt.ok_or_else(|| WpdError::ObjectNotFound {
            device_id: device_id.to_string(),
            object_id: object_id.to_string(),
        })?;

        let chunk_size = (opt_buf_size as usize).clamp(16 * 1024, 1024 * 1024);
        let mut buf = vec![0u8; chunk_size];
        let mut total: u64 = 0;

        loop {
            let mut bytes_read: u32 = 0;
            let hr = unsafe {
                stream.Read(
                    buf.as_mut_ptr() as *mut c_void,
                    chunk_size as u32,
                    Some(&mut bytes_read),
                )
            };
            if hr.is_err() {
                return Err(map_win_err(windows::core::Error::from(hr)));
            }
            if bytes_read == 0 {
                break;
            }
            let next_total = total.saturating_add(u64::from(bytes_read));
            if let Some(cap) = max_bytes
                && next_total > cap
            {
                return Err(WpdError::InvalidQuery(format!(
                    "object '{object_id}' exceeds max_copy_bytes limit ({cap} bytes)"
                )));
            }
            writer.write_all(&buf[..bytes_read as usize])?;
            total = next_total;
            if hr == S_FALSE {
                break;
            }
        }
        writer.flush()?;
        Ok(total)
    }

    fn delete_object(&self, device_id: &str, object_id: &str) -> Result<(), WpdError> {
        let _com = ComGuard::init_mta()?;
        let guard = OpenDeviceGuard::open(device_id, true)?;
        let content = guard.content()?;
        let prop_col: IPortableDevicePropVariantCollection =
            unsafe { CoCreateInstance(&PortableDevicePropVariantCollection, None, CLSCTX_INPROC_SERVER) }
                .map_err(map_win_err)?;

        let mut wide: Vec<u16> = object_id.encode_utf16().chain(std::iter::once(0)).collect();
        let mut pv = PROPVARIANT::default();
        unsafe {
            {
                let inner = &mut *pv.Anonymous.Anonymous;
                inner.vt = VT_LPWSTR;
                inner.Anonymous.pwszVal = PWSTR(wide.as_mut_ptr());
            }
            // Keep `wide` alive across `Add` (Add copies the string into the collection); zero pv before drop.
            let add_res = prop_col.Add(&pv);
            {
                let inner = &mut *pv.Anonymous.Anonymous;
                inner.vt = Default::default();
                inner.Anonymous.pwszVal = PWSTR::null();
            }
            add_res.map_err(map_win_err)?;
            content
                .Delete(
                    PORTABLE_DEVICE_DELETE_NO_RECURSION.0 as u32,
                    &prop_col,
                    std::ptr::null_mut(),
                )
                .map_err(map_win_err)?;
        }
        Ok(())
    }
}
