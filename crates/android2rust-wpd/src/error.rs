use thiserror::Error;

#[derive(Debug, Error)]
pub enum WpdError {
    #[error("no WPD/MTP portable devices detected")]
    NoDevices,

    #[error("access denied on WPD/MTP device: {0}")]
    AccessDenied(String),

    #[error("WPD/MTP live COM enumeration is only supported on Windows")]
    UnsupportedPlatform,

    #[error("WPD/MTP device not found: {0}")]
    DeviceNotFound(String),

    #[error("WPD/MTP object '{object_id}' not found on device '{device_id}'")]
    ObjectNotFound { device_id: String, object_id: String },

    #[error("unsafe path or traversal rejected during MTP copy-out: {0}")]
    PathTraversal(String),

    #[error("invalid mobile file search query: {0}")]
    InvalidQuery(String),

    #[error("Windows Portable Devices COM error: {0}")]
    ComError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("export error: {0}")]
    Export(#[from] guap_export::ExportError),
}
