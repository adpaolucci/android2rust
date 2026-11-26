#![deny(unsafe_code)]

pub mod copy;
pub mod dir_source;
pub mod error;
#[cfg(windows)]
#[allow(unsafe_code)]
mod live;
#[cfg(not(windows))]
#[path = "live_stub.rs"]
mod live;
pub mod mock_source;
pub mod model;
pub mod query;
pub mod source;
pub mod table;

pub use copy::{copy_out, safe_relative_copy_path};
pub use dir_source::DirectoryMtpSource;
pub use error::WpdError;
pub use live::LiveWpdSource;
pub use mock_source::{MockErrorKind, MockWpdSource};
pub use model::{CopyOutOptions, CopyOutRecord, MobileFileQuery, WpdDeviceInfo, WpdObjectEntry, WpdStorageInfo};
pub use query::search_devices;
pub use source::{MtpDeviceSource, infer_extension, infer_mime_from_extension};
pub use table::{
    MobileFileSearchProvider, WpdDevicesProvider, entries_to_table_data, export_wpd_entries_bytes,
    mobile_file_search_schema, wpd_devices_schema, wpd_entry_to_row, write_wpd_entries_export,
};
