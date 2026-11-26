use std::path::Path;

use guap_export::{CustodyManifest, ExportFormat, ExportOptions, export_table, write_table_export};
use guap_table::{
    CellValue, ColumnDef, ColumnType, InMemoryTableProvider, Row, SortDirection, TableData, TableError, TableProvider,
    TableQuery, TableSchema,
};

use crate::error::WpdError;
use crate::model::{WpdDeviceInfo, WpdObjectEntry};

pub fn mobile_file_search_schema() -> TableSchema {
    TableSchema::new(
        "mobile_file_search",
        "MobileFileSearch (WPD/MTP)",
        vec![
            ColumnDef::new("device_name", "DeviceName", ColumnType::Text).with_width_hint(140),
            ColumnDef::new("storage_name", "StorageName", ColumnType::Text).with_width_hint(130),
            ColumnDef::new("object_id", "ObjectID", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("full_path", "FullPath", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("extension", "Extension", ColumnType::Text).with_width_hint(75),
            ColumnDef::new("size_bytes", "SizeBytes", ColumnType::BytesSize).with_width_hint(100),
            ColumnDef::new("created_time", "CreatedTime", ColumnType::Timestamp).with_width_hint(165),
            ColumnDef::new("modified_time", "ModifiedTime", ColumnType::Timestamp).with_width_hint(165),
            ColumnDef::new("content_type", "ContentType", ColumnType::Text).with_width_hint(140),
        ],
    )
    .with_default_sort(3, SortDirection::Asc)
}

pub fn wpd_entry_to_row(id: u64, entry: &WpdObjectEntry) -> Row {
    let cells = vec![
        CellValue::Text(entry.device_name.clone()),
        CellValue::Text(entry.storage_name.clone()),
        CellValue::Text(entry.object_id.clone()),
        CellValue::Text(entry.full_path.clone()),
        CellValue::Text(entry.filename.clone()),
        CellValue::Text(entry.extension.clone()),
        CellValue::Bytes(entry.size_bytes),
        entry.created_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
        entry.modified_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
        CellValue::Text(entry.content_type.clone()),
    ];
    let detail = serde_json::to_value(entry).ok();
    let mut row = Row::new(id, cells);
    if let Some(d) = detail {
        row = row.with_detail_json(d);
    }
    row
}

pub fn entries_to_table_data(entries: &[WpdObjectEntry]) -> TableData {
    let schema = mobile_file_search_schema();
    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(idx, e)| wpd_entry_to_row(idx as u64, e))
        .collect();
    let total_rows = rows.len();
    TableData {
        schema,
        rows,
        total_rows,
    }
}

#[derive(Debug, Clone)]
pub struct MobileFileSearchProvider {
    inner: InMemoryTableProvider,
}

impl MobileFileSearchProvider {
    pub fn new(entries: &[WpdObjectEntry]) -> Self {
        let data = entries_to_table_data(entries);
        Self {
            inner: InMemoryTableProvider::new(
                "android2rust_mobile_file_search",
                "Search files on connected Windows Portable Devices (WPD/MTP) or synthetic directory fixtures",
                data.schema,
                data.rows,
            ),
        }
    }
}

impl TableProvider for MobileFileSearchProvider {
    fn tool_id(&self) -> &'static str {
        self.inner.tool_id()
    }

    fn description(&self) -> &'static str {
        self.inner.description()
    }

    fn schema(&self) -> TableSchema {
        self.inner.schema()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.inner.query(req)
    }
}

pub fn wpd_devices_schema() -> TableSchema {
    TableSchema::new(
        "android2rust_wpd_devices",
        "WPD / MTP Portable Devices",
        vec![
            ColumnDef::new("device_id", "DeviceID", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("friendly_name", "FriendlyName", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("manufacturer", "Manufacturer", ColumnType::Text).with_width_hint(140),
            ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("storage_count", "StorageCount", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("storages", "Storages", ColumnType::Text).with_width_hint(220),
        ],
    )
    .with_default_sort(1, SortDirection::Asc)
}

#[derive(Debug, Clone)]
pub struct WpdDevicesProvider {
    inner: InMemoryTableProvider,
}

impl WpdDevicesProvider {
    pub fn new(devices: &[WpdDeviceInfo]) -> Self {
        let schema = wpd_devices_schema();
        let rows: Vec<Row> = devices
            .iter()
            .enumerate()
            .map(|(idx, d)| {
                let storage_names = d
                    .storages
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                let mut row = Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(d.id.clone()),
                        CellValue::Text(d.friendly_name.clone()),
                        CellValue::Text(d.manufacturer.clone()),
                        CellValue::Text(d.description.clone()),
                        CellValue::Uint(d.storages.len() as u64),
                        CellValue::Text(storage_names),
                    ],
                );
                if let Ok(detail) = serde_json::to_value(d) {
                    row = row.with_detail_json(detail);
                }
                row
            })
            .collect();
        Self {
            inner: InMemoryTableProvider::new(
                "android2rust_wpd_devices",
                "Enumerate connected Windows Portable Devices (WPD/MTP) and their storages",
                schema,
                rows,
            ),
        }
    }
}

impl TableProvider for WpdDevicesProvider {
    fn tool_id(&self) -> &'static str {
        self.inner.tool_id()
    }

    fn description(&self) -> &'static str {
        self.inner.description()
    }

    fn schema(&self) -> TableSchema {
        self.inner.schema()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.inner.query(req)
    }
}

pub fn export_wpd_entries_bytes(
    entries: &[WpdObjectEntry],
    format: ExportFormat,
    opts: &ExportOptions,
) -> Result<Vec<u8>, WpdError> {
    let data = entries_to_table_data(entries);
    Ok(export_table(&data, format, opts)?)
}

pub fn write_wpd_entries_export(
    entries: &[WpdObjectEntry],
    path: &Path,
    format: ExportFormat,
    opts: &ExportOptions,
) -> Result<CustodyManifest, WpdError> {
    let data = entries_to_table_data(entries);
    Ok(write_table_export(&data, path, format, opts)?)
}
