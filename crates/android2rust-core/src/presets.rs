use crate::model::{
    AndroidJob, AndroidOperation, BackupOptions, LogcatOptions, PackageOptions, ToolFamily, TransferOptions,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobPreset {
    pub id: String,
    pub name: String,
    pub category: String,
    pub summary: String,
    pub destructive: bool,
    pub job: AndroidJob,
}

pub fn builtin_presets() -> Vec<JobPreset> {
    vec![
        JobPreset {
            id: "device-triage".to_string(),
            name: "Device Inventory (adb devices -l)".to_string(),
            category: "Discovery".to_string(),
            summary: "Enumerate connected Android USB/emulator transports, product models, and USB paths.".to_string(),
            destructive: false,
            job: AndroidJob {
                name: "Device Inventory".to_string(),
                description: "Enumerate connected ADB transports with transport IDs and models".to_string(),
                tool: ToolFamily::Adb,
                operation: AndroidOperation::Devices,
                ..Default::default()
            },
        },
        JobPreset {
            id: "props-fingerprint".to_string(),
            name: "Device Props & OS Fingerprint".to_string(),
            category: "Discovery".to_string(),
            summary: "Query Android build fingerprint, API level, security patch, and bootloader state via getprop.".to_string(),
            destructive: false,
            job: AndroidJob {
                name: "System Properties Snapshot".to_string(),
                description: "Collect ro.* device properties via adb shell getprop".to_string(),
                tool: ToolFamily::Adb,
                operation: AndroidOperation::DeviceProps,
                ..Default::default()
            },
        },
        JobPreset {
            id: "third-party-packages".to_string(),
            name: "3rd-Party Package Audit (-3 -f -i)".to_string(),
            category: "Packages".to_string(),
            summary: "List installed third-party APKs with base.apk paths and installer package origins.".to_string(),
            destructive: false,
            job: AndroidJob {
                name: "Third-Party APK Audit".to_string(),
                description: "Audit user-installed APKs, paths, and installer attribution".to_string(),
                tool: ToolFamily::Adb,
                operation: AndroidOperation::Packages,
                package_opts: PackageOptions {
                    third_party_only: true,
                    show_apk_path: true,
                    show_installer: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        },
        JobPreset {
            id: "apk-install-grant".to_string(),
            name: "Install APK (-r -g)".to_string(),
            category: "Packages".to_string(),
            summary: "Install or upgrade a local APK while preserving data (-r) and auto-granting runtime permissions (-g).".to_string(),
            destructive: false,
            job: AndroidJob {
                name: "APK Install + Permissions".to_string(),
                description: "Deploy local APK with reinstall and runtime permission grant".to_string(),
                tool: ToolFamily::Adb,
                operation: AndroidOperation::InstallApk,
                package_opts: PackageOptions {
                    reinstall: true,
                    grant_permissions: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        },
        JobPreset {
            id: "logcat-crash-snapshot".to_string(),
            name: "Logcat Crash & System Snapshot".to_string(),
            category: "Diagnostics".to_string(),
            summary: "Capture the last 500 threadtime lines across main, system, and crash log buffers (-d).".to_string(),
            destructive: false,
            job: AndroidJob {
                name: "Logcat Crash Snapshot".to_string(),
                description: "Non-blocking dump of main/system/crash buffers".to_string(),
                tool: ToolFamily::Adb,
                operation: AndroidOperation::Logcat,
                logcat_opts: LogcatOptions {
                    buffers: vec!["main".to_string(), "system".to_string(), "crash".to_string()],
                    dump_and_exit: true,
                    clear_first: false,
                    format: "threadtime".to_string(),
                    filter_specs: Vec::new(),
                    max_lines: Some(500),
                },
                ..Default::default()
            },
        },
        JobPreset {
            id: "adb-pull-evidence".to_string(),
            name: "Pull Remote Media / Artifacts (-a)".to_string(),
            category: "Transfer".to_string(),
            summary: "Pull remote device files to the local workstation while preserving timestamps (-a).".to_string(),
            destructive: false,
            job: AndroidJob {
                name: "ADB Pull Preservation".to_string(),
                description: "Extract remote /sdcard artifacts with timestamp preservation".to_string(),
                tool: ToolFamily::Adb,
                operation: AndroidOperation::Pull,
                source_path: "/sdcard/Download".to_string(),
                transfer_opts: TransferOptions {
                    preserve_timestamps: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        },
        JobPreset {
            id: "fastboot-flash-image".to_string(),
            name: "Fastboot Flash Partition Image".to_string(),
            category: "Fastboot".to_string(),
            summary: "Flash a verified .img file to a target partition (e.g. boot / init_boot) with Dry-Run pre-flight.".to_string(),
            destructive: true,
            job: AndroidJob {
                name: "Fastboot Flash Partition".to_string(),
                description: "Flash local partition image via fastboot (guarded)".to_string(),
                tool: ToolFamily::Fastboot,
                operation: AndroidOperation::FastbootFlash,
                backup_opts: BackupOptions::default(),
                ..Default::default()
            },
        },
        JobPreset {
            id: "forensic-artifact-inspect".to_string(),
            name: "Offline Forensic Artifact Audit (.apk/.ab/.db)".to_string(),
            category: "Forensics".to_string(),
            summary: "100% pure-Rust offline SHA-256 chain-of-custody & metadata extraction for APK, .ab backups, SQLite DBs, and XML.".to_string(),
            destructive: false,
            job: AndroidJob {
                name: "Offline Forensic Inspection".to_string(),
                description: "Pure-Rust inspection of APK manifests, .ab zlib TAR backups, SQLite schemas, and XML".to_string(),
                tool: ToolFamily::Forensics,
                operation: AndroidOperation::InspectArtifact,
                ..Default::default()
            },
        },
    ]
}

pub fn find_preset(id_or_name: &str) -> Option<JobPreset> {
    let needle = id_or_name.trim();
    builtin_presets()
        .into_iter()
        .find(|p| p.id.eq_ignore_ascii_case(needle) || p.name.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_eight_presets_with_destructive_flag() {
        let all = builtin_presets();
        assert_eq!(all.len(), 8);
        assert!(find_preset("fastboot-flash-image").unwrap().destructive);
        assert!(!find_preset("forensic-artifact-inspect").unwrap().destructive);
    }
}
