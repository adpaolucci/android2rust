use std::path::Path;

use android2rust_wpd::{
    MobileFileSearchProvider, WpdDeviceInfo, WpdDevicesProvider, WpdObjectEntry, export_wpd_entries_bytes,
    write_wpd_entries_export,
};
use anyhow::Result;
use guap_export::{CustodyManifest, ExportFormat, ExportOptions};

pub fn wpd_entries_to_table_provider(entries: &[WpdObjectEntry]) -> MobileFileSearchProvider {
    MobileFileSearchProvider::new(entries)
}

pub fn wpd_devices_to_table_provider(devices: &[WpdDeviceInfo]) -> WpdDevicesProvider {
    WpdDevicesProvider::new(devices)
}

pub fn export_wpd_results(entries: &[WpdObjectEntry], format: ExportFormat, output: &Path) -> Result<CustodyManifest> {
    let opts = ExportOptions::default();
    Ok(write_wpd_entries_export(entries, output, format, &opts)?)
}

pub fn export_wpd_results_bytes(entries: &[WpdObjectEntry], format: ExportFormat) -> Result<Vec<u8>> {
    let opts = ExportOptions::default();
    Ok(export_wpd_entries_bytes(entries, format, &opts)?)
}
