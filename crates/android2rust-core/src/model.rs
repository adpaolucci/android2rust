use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ToolFamily {
    #[default]
    Adb,
    Fastboot,
    Forensics,
    Wpd,
}

impl ToolFamily {
    pub fn binary_name(self) -> &'static str {
        match self {
            Self::Adb => "adb",
            Self::Fastboot => "fastboot",
            Self::Forensics => "android2rust inspect",
            Self::Wpd => "android2rust mtp",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Adb => "ADB",
            Self::Fastboot => "Fastboot",
            Self::Forensics => "Offline Forensics",
            Self::Wpd => "WPD / MTP",
        }
    }
}

impl fmt::Display for ToolFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TransportMode {
    #[default]
    Auto,
    Usb,
    Emulator,
    Serial(String),
    TransportId(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RebootTarget {
    #[default]
    System,
    Bootloader,
    Recovery,
    Fastbootd,
    Sideload,
}

impl RebootTarget {
    pub fn as_arg(self) -> Option<&'static str> {
        match self {
            Self::System => None,
            Self::Bootloader => Some("bootloader"),
            Self::Recovery => Some("recovery"),
            Self::Fastbootd => Some("fastboot"),
            Self::Sideload => Some("sideload"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::System => "System OS",
            Self::Bootloader => "Bootloader",
            Self::Recovery => "Recovery",
            Self::Fastbootd => "Userspace Fastbootd",
            Self::Sideload => "ADB Sideload",
        }
    }
}

impl fmt::Display for RebootTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AndroidOperation {
    // ADB operations
    #[default]
    Devices,
    DeviceProps,
    Packages,
    InstallApk,
    UninstallPackage,
    DisablePackage,
    EnablePackage,
    Pull,
    Push,
    BackupAb,
    RestoreAb,
    Bugreport,
    Logcat,
    Dumpsys,
    Shell,
    Sideload,
    Reboot,
    // Fastboot operations
    FastbootDevices,
    FastbootGetvar,
    FastbootFlash,
    FastbootBoot,
    FastbootErase,
    FastbootFormat,
    FastbootFlashingUnlock,
    FastbootFlashingLock,
    FastbootReboot,
    // Pure-Rust offline forensics
    InspectArtifact,
    // WPD / MTP Mobile File Search
    MobileFileSearch,
}

impl AndroidOperation {
    pub const ALL: &'static [Self] = &[
        Self::Devices,
        Self::DeviceProps,
        Self::Packages,
        Self::InstallApk,
        Self::UninstallPackage,
        Self::DisablePackage,
        Self::EnablePackage,
        Self::Pull,
        Self::Push,
        Self::BackupAb,
        Self::RestoreAb,
        Self::Bugreport,
        Self::Logcat,
        Self::Dumpsys,
        Self::Shell,
        Self::Sideload,
        Self::Reboot,
        Self::FastbootDevices,
        Self::FastbootGetvar,
        Self::FastbootFlash,
        Self::FastbootBoot,
        Self::FastbootErase,
        Self::FastbootFormat,
        Self::FastbootFlashingUnlock,
        Self::FastbootFlashingLock,
        Self::FastbootReboot,
        Self::InspectArtifact,
        Self::MobileFileSearch,
    ];

    pub fn default_tool(self) -> ToolFamily {
        match self {
            Self::FastbootDevices
            | Self::FastbootGetvar
            | Self::FastbootFlash
            | Self::FastbootBoot
            | Self::FastbootErase
            | Self::FastbootFormat
            | Self::FastbootFlashingUnlock
            | Self::FastbootFlashingLock
            | Self::FastbootReboot => ToolFamily::Fastboot,
            Self::InspectArtifact => ToolFamily::Forensics,
            Self::MobileFileSearch => ToolFamily::Wpd,
            _ => ToolFamily::Adb,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Devices => "adb devices -l",
            Self::DeviceProps => "adb shell getprop",
            Self::Packages => "adb shell pm list packages",
            Self::InstallApk => "adb install",
            Self::UninstallPackage => "adb uninstall",
            Self::DisablePackage => "adb shell pm disable-user",
            Self::EnablePackage => "adb shell pm enable",
            Self::Pull => "adb pull",
            Self::Push => "adb push",
            Self::BackupAb => "adb backup (.ab)",
            Self::RestoreAb => "adb restore (.ab)",
            Self::Bugreport => "adb bugreport",
            Self::Logcat => "adb logcat",
            Self::Dumpsys => "adb shell dumpsys",
            Self::Shell => "adb shell",
            Self::Sideload => "adb sideload",
            Self::Reboot => "adb reboot",
            Self::FastbootDevices => "fastboot devices",
            Self::FastbootGetvar => "fastboot getvar",
            Self::FastbootFlash => "fastboot flash",
            Self::FastbootBoot => "fastboot boot",
            Self::FastbootErase => "fastboot erase",
            Self::FastbootFormat => "fastboot format",
            Self::FastbootFlashingUnlock => "fastboot flashing unlock",
            Self::FastbootFlashingLock => "fastboot flashing lock",
            Self::FastbootReboot => "fastboot reboot",
            Self::InspectArtifact => "Inspect Local Artifact (Offline Forensics)",
            Self::MobileFileSearch => "Mobile File Search (WPD/MTP)",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Devices => "devices",
            Self::DeviceProps => "props",
            Self::Packages => "packages",
            Self::InstallApk => "install",
            Self::UninstallPackage => "uninstall",
            Self::DisablePackage => "disable",
            Self::EnablePackage => "enable",
            Self::Pull => "pull",
            Self::Push => "push",
            Self::BackupAb => "backup",
            Self::RestoreAb => "restore",
            Self::Bugreport => "bugreport",
            Self::Logcat => "logcat",
            Self::Dumpsys => "dumpsys",
            Self::Shell => "shell",
            Self::Sideload => "sideload",
            Self::Reboot => "reboot",
            Self::FastbootDevices => "fastboot-devices",
            Self::FastbootGetvar => "fastboot-getvar",
            Self::FastbootFlash => "fastboot-flash",
            Self::FastbootBoot => "fastboot-boot",
            Self::FastbootErase => "fastboot-erase",
            Self::FastbootFormat => "fastboot-format",
            Self::FastbootFlashingUnlock => "fastboot-unlock",
            Self::FastbootFlashingLock => "fastboot-lock",
            Self::FastbootReboot => "fastboot-reboot",
            Self::InspectArtifact => "inspect",
            Self::MobileFileSearch => "mtp-search",
        }
    }

    pub fn from_slug(raw: &str) -> Option<Self> {
        let norm = raw.trim().to_ascii_lowercase();
        match norm.as_str() {
            "mobile-search" | "mobile-file-search" | "wpd-search" => Some(Self::MobileFileSearch),
            _ => Self::ALL.iter().copied().find(|op| op.slug() == norm),
        }
    }
}

impl fmt::Display for AndroidOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PackageOptions {
    pub third_party_only: bool,
    pub system_only: bool,
    pub show_apk_path: bool,
    pub show_installer: bool,
    pub show_uid: bool,
    pub reinstall: bool,
    pub allow_downgrade: bool,
    pub grant_permissions: bool,
    pub keep_data: bool,
    pub user_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransferOptions {
    pub preserve_timestamps: bool,
    pub sync_only_newer: bool,
    pub compression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogcatOptions {
    pub buffers: Vec<String>,
    pub dump_and_exit: bool,
    pub clear_first: bool,
    pub format: String,
    pub filter_specs: Vec<String>,
    pub max_lines: Option<u32>,
}

impl Default for LogcatOptions {
    fn default() -> Self {
        Self {
            buffers: vec!["main".to_string(), "system".to_string()],
            dump_and_exit: true,
            clear_first: false,
            format: "threadtime".to_string(),
            filter_specs: Vec::new(),
            max_lines: Some(500),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupOptions {
    pub include_apk: bool,
    pub include_obb: bool,
    pub include_shared: bool,
    pub all_apps: bool,
    pub include_system: bool,
    pub packages: Vec<String>,
}

impl Default for BackupOptions {
    fn default() -> Self {
        Self {
            include_apk: true,
            include_obb: false,
            include_shared: false,
            all_apps: true,
            include_system: false,
            packages: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastbootOptions {
    pub partition: String,
    pub slot: Option<String>,
    pub skip_reboot: bool,
    pub wipe_userdata: bool,
    pub disable_verity: bool,
    pub disable_verification: bool,
}

impl Default for FastbootOptions {
    fn default() -> Self {
        Self {
            partition: "boot".to_string(),
            slot: None,
            skip_reboot: false,
            wipe_userdata: false,
            disable_verity: false,
            disable_verification: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CaseMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examiner: Option<String>,
}

impl CaseMetadata {
    pub fn is_empty(&self) -> bool {
        self.case_id.as_deref().is_none_or(|s| s.trim().is_empty())
            && self.evidence_id.as_deref().is_none_or(|s| s.trim().is_empty())
            && self.examiner.as_deref().is_none_or(|s| s.trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicOptions {
    pub compute_sha256: bool,
    pub extract_manifest_permissions: bool,
    pub inspect_sqlite_tables: bool,
    pub inspect_ab_tar_entries: bool,
    pub max_entries: usize,
    #[serde(default)]
    pub case_meta: CaseMetadata,
    #[serde(skip)]
    pub ab_password: Option<String>,
}

impl Default for ForensicOptions {
    fn default() -> Self {
        Self {
            compute_sha256: true,
            extract_manifest_permissions: true,
            inspect_sqlite_tables: true,
            inspect_ab_tar_entries: true,
            max_entries: 2000,
            case_meta: CaseMetadata::default(),
            ab_password: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WpdSearchOptions {
    pub pattern: String,
    pub use_regex: bool,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub created_after: Option<String>,
    pub created_before: Option<String>,
    pub modified_after: Option<String>,
    pub modified_before: Option<String>,
    pub mime_or_ext: Option<String>,
    pub max_results: Option<usize>,
    pub device_filter: Option<String>,
    pub copy_out_dir: Option<String>,
    pub offline_source_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidJob {
    pub name: String,
    pub description: String,
    pub tool: ToolFamily,
    pub operation: AndroidOperation,
    pub serial: String,
    pub transport: TransportMode,
    /// Local path (APK, `.ab`, `.db`, image, push source, or pull destination) or remote path for `pull`.
    pub source_path: String,
    /// Remote device path, local output destination, package ID, dumpsys service, shell command, or reboot/getvar target.
    pub target_path: String,
    pub reboot_target: RebootTarget,
    pub package_opts: PackageOptions,
    pub transfer_opts: TransferOptions,
    pub logcat_opts: LogcatOptions,
    pub backup_opts: BackupOptions,
    pub fastboot_opts: FastbootOptions,
    pub forensic_opts: ForensicOptions,
    #[serde(default)]
    pub wpd_opts: WpdSearchOptions,
    pub dry_run: bool,
    pub extra_args: Vec<String>,
}

impl Default for AndroidJob {
    fn default() -> Self {
        Self {
            name: "Device Inventory & Properties".to_string(),
            description: "Inspect connected Android devices via adb devices -l".to_string(),
            tool: ToolFamily::Adb,
            operation: AndroidOperation::Devices,
            serial: String::new(),
            transport: TransportMode::Auto,
            source_path: String::new(),
            target_path: String::new(),
            reboot_target: RebootTarget::System,
            package_opts: PackageOptions::default(),
            transfer_opts: TransferOptions::default(),
            logcat_opts: LogcatOptions::default(),
            backup_opts: BackupOptions::default(),
            fastboot_opts: FastbootOptions::default(),
            forensic_opts: ForensicOptions::default(),
            wpd_opts: WpdSearchOptions::default(),
            dry_run: false,
            extra_args: Vec::new(),
        }
    }
}

impl AndroidJob {
    pub fn with_dry_run(&self) -> Self {
        let mut copy = self.clone();
        copy.dry_run = true;
        copy
    }

    pub fn effective_transport(&self) -> TransportMode {
        if !self.serial.trim().is_empty() && matches!(self.transport, TransportMode::Auto) {
            TransportMode::Serial(self.serial.trim().to_string())
        } else {
            self.transport.clone()
        }
    }

    pub fn is_destructive(&self) -> bool {
        !self.destructive_reasons().is_empty()
    }

    pub fn destructive_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        match self.operation {
            AndroidOperation::FastbootFlash => {
                let part = if self.fastboot_opts.partition.trim().is_empty() {
                    self.target_path.trim()
                } else {
                    self.fastboot_opts.partition.trim()
                };
                reasons.push(format!(
                    "fastboot flash {}",
                    if part.is_empty() { "<partition>" } else { part }
                ));
            }
            AndroidOperation::FastbootErase => reasons.push("fastboot erase".to_string()),
            AndroidOperation::FastbootFormat => reasons.push("fastboot format".to_string()),
            AndroidOperation::FastbootFlashingUnlock => {
                reasons.push("fastboot flashing unlock (wipes userdata)".to_string())
            }
            AndroidOperation::FastbootFlashingLock => {
                reasons.push("fastboot flashing lock (wipes userdata)".to_string())
            }
            AndroidOperation::RestoreAb => reasons.push("adb restore (overwrites app data)".to_string()),
            AndroidOperation::Sideload => reasons.push("adb sideload (flashes OTA update ZIP)".to_string()),
            AndroidOperation::UninstallPackage if !self.package_opts.keep_data => {
                reasons.push("adb uninstall (removes package & app data)".to_string());
            }
            AndroidOperation::Shell => {
                let lower = self.target_path.to_ascii_lowercase();
                for pat in [
                    "rm -rf",
                    "rm -fr",
                    "rm -r ",
                    "dd ",
                    "pm clear",
                    "pm uninstall",
                    "cmd package uninstall",
                    "wipe",
                    "format ",
                    "flash_image",
                ] {
                    if lower.contains(pat) {
                        reasons.push(format!("adb shell contains destructive token '{pat}'"));
                        break;
                    }
                }
            }
            _ => {}
        }

        if self.fastboot_opts.wipe_userdata
            && matches!(
                self.operation,
                AndroidOperation::FastbootFlash | AndroidOperation::FastbootErase | AndroidOperation::FastbootFormat
            )
        {
            reasons.push("fastboot -w (wipe userdata & cache)".to_string());
        }
        reasons
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_destructive_operations() {
        let mut job = AndroidJob::default();
        assert!(!job.is_destructive());

        job.operation = AndroidOperation::FastbootFlash;
        job.tool = ToolFamily::Fastboot;
        assert!(job.is_destructive());
        assert!(job.destructive_reasons()[0].contains("fastboot flash"));

        job.operation = AndroidOperation::UninstallPackage;
        job.tool = ToolFamily::Adb;
        job.fastboot_opts.wipe_userdata = false;
        assert!(job.is_destructive());
        job.package_opts.keep_data = true;
        assert!(!job.is_destructive());

        job.operation = AndroidOperation::Shell;
        job.target_path = "pm clear com.example.app".to_string();
        assert!(job.is_destructive());

        job.operation = AndroidOperation::Devices;
        job.tool = ToolFamily::Adb;
        job.target_path.clear();
        job.fastboot_opts.wipe_userdata = true;
        assert!(!job.is_destructive());
    }

    #[test]
    fn deserializes_legacy_android_job_json_without_wpd_opts() {
        let legacy_json = r#"{
            "name": "Legacy ADB Pull",
            "description": "Pull DCIM from device",
            "tool": "Adb",
            "operation": "Pull",
            "serial": "R58M123",
            "transport": { "Serial": "R58M123" },
            "source_path": "/sdcard/DCIM",
            "target_path": "C:\\Backup",
            "reboot_target": "System",
            "package_opts": {
                "reinstall": false,
                "allow_downgrade": false,
                "grant_permissions": false,
                "keep_data": false,
                "third_party_only": false,
                "system_only": false,
                "show_apk_path": false,
                "show_installer": false,
                "show_uid": false,
                "user_id": null
            },
            "transfer_opts": {
                "preserve_timestamps": true,
                "sync_only_newer": false,
                "compression": null
            },
            "logcat_opts": {
                "buffers": ["main"],
                "format": "threadtime",
                "clear_first": false,
                "dump_and_exit": true,
                "max_lines": 500,
                "filter_specs": []
            },
            "backup_opts": {
                "include_apk": false,
                "include_obb": false,
                "include_shared": false,
                "all_apps": false,
                "include_system": false,
                "packages": []
            },
            "fastboot_opts": {
                "partition": "",
                "slot": null,
                "wipe_userdata": false,
                "skip_reboot": false,
                "disable_verity": false,
                "disable_verification": false
            },
            "forensic_opts": {
                "compute_sha256": true,
                "extract_manifest_permissions": true,
                "inspect_sqlite_tables": true,
                "inspect_ab_tar_entries": true,
                "max_entries": 2000,
                "case_meta": {}
            },
            "dry_run": false,
            "extra_args": []
        }"#;

        let job: AndroidJob = serde_json::from_str(legacy_json).expect("legacy AndroidJob JSON must deserialize");
        assert_eq!(job.name, "Legacy ADB Pull");
        assert_eq!(job.operation, AndroidOperation::Pull);
        assert_eq!(job.serial, "R58M123");
        assert_eq!(job.wpd_opts, WpdSearchOptions::default());

        let mut val = serde_json::to_value(AndroidJob::default()).unwrap();
        val.as_object_mut().unwrap().remove("wpd_opts");
        let roundtrip: AndroidJob = serde_json::from_value(val).expect("AndroidJob without wpd_opts must deserialize");
        assert_eq!(roundtrip.wpd_opts, WpdSearchOptions::default());
    }
}
