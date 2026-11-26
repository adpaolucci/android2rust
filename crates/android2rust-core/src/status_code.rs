use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusSeverity {
    Success,
    Warning,
    Error,
    Fatal,
}

impl StatusSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::Warning => "Warning",
            Self::Error => "Error",
            Self::Fatal => "Fatal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusCodeInfo {
    pub code: String,
    pub exit_code: Option<i32>,
    pub severity: StatusSeverity,
    pub is_success: bool,
    pub short_label: String,
    pub summary: String,
    pub details: Vec<String>,
}

pub fn decode_exit_code(code: i32) -> StatusCodeInfo {
    match code {
        0 => StatusCodeInfo {
            code: "0".to_string(),
            exit_code: Some(0),
            severity: StatusSeverity::Success,
            is_success: true,
            short_label: "0 (Success)".to_string(),
            summary: "Command or inspection completed cleanly with exit code 0.".to_string(),
            details: vec!["Exit code 0: No errors encountered.".to_string()],
        },
        -1 => StatusCodeInfo {
            code: "-1".to_string(),
            exit_code: Some(-1),
            severity: StatusSeverity::Warning,
            is_success: false,
            short_label: "-1 (Cancelled)".to_string(),
            summary: "Execution was cancelled by user or caller before completion.".to_string(),
            details: vec!["Process terminated cleanly via CancelToken.".to_string()],
        },
        1 => StatusCodeInfo {
            code: "1".to_string(),
            exit_code: Some(1),
            severity: StatusSeverity::Error,
            is_success: false,
            short_label: "1 (Command Error)".to_string(),
            summary:
                "ADB/Fastboot returned exit code 1 (invalid arguments, device offline/missing, or rejected operation)."
                    .to_string(),
            details: vec![
                "Verify device connection via `adb devices -l` or `fastboot devices`.".to_string(),
                "Check USB debugging authorization prompt on device screen.".to_string(),
            ],
        },
        127 => StatusCodeInfo {
            code: "127".to_string(),
            exit_code: Some(127),
            severity: StatusSeverity::Fatal,
            is_success: false,
            short_label: "127 (Binary / Command Not Found)".to_string(),
            summary: "Requested executable or shell subcommand was not found.".to_string(),
            details: vec!["Install Android Platform-Tools or set ANDROID_HOME / PATH.".to_string()],
        },
        255 => StatusCodeInfo {
            code: "255".to_string(),
            exit_code: Some(255),
            severity: StatusSeverity::Fatal,
            is_success: false,
            short_label: "255 (Daemon / Transport Failure)".to_string(),
            summary: "ADB daemon transport lost connection or received an unexpected protocol error.".to_string(),
            details: vec!["Run `adb kill-server && adb start-server` or reconnect USB cable.".to_string()],
        },
        other => StatusCodeInfo {
            code: other.to_string(),
            exit_code: Some(other),
            severity: StatusSeverity::Error,
            is_success: false,
            short_label: format!("{other} (Non-Zero Exit)"),
            summary: format!("Process exited with non-zero status code {other}."),
            details: vec![format!("Non-zero exit code: {other}")],
        },
    }
}

pub fn decode_status_code(raw: &str) -> StatusCodeInfo {
    let trimmed = raw.trim();
    if let Ok(num) = trimmed.parse::<i32>() {
        return decode_exit_code(num);
    }

    let upper = trimmed.to_ascii_uppercase();
    let (label, summary, details, sev, ok) = match upper.as_str() {
        "SUCCESS" | "OKAY" => (
            upper.clone(),
            "Operation succeeded cleanly on target Android device.",
            vec!["Android Package Manager / Fastboot returned success."],
            StatusSeverity::Success,
            true,
        ),
        "DEVICE_UNAUTHORIZED" | "UNAUTHORIZED" => (
            "DEVICE_UNAUTHORIZED".to_string(),
            "USB debugging RSA key prompt has not been accepted on the Android device.",
            vec![
                "Unlock the Android device screen and tap 'Allow USB debugging'.",
                "Check 'Always allow from this computer' to persist ADB RSA trust.",
                "If no prompt appears, toggle USB debugging off/on in Developer Options.",
            ],
            StatusSeverity::Warning,
            false,
        ),
        "DEVICE_OFFLINE" | "OFFLINE" => (
            "DEVICE_OFFLINE".to_string(),
            "ADB sees the device USB endpoint, but the adbd daemon is unresponsive.",
            vec![
                "Reconnect USB cable directly to host port (avoid unpowered hubs).",
                "Run `adb reconnect` or restart ADB server (`adb kill-server`).",
            ],
            StatusSeverity::Error,
            false,
        ),
        "NO_DEVICES_FOUND" | "NO_DEVICE" => (
            "NO_DEVICES_FOUND".to_string(),
            "No ADB or Fastboot devices/emulators matched the specified transport.",
            vec![
                "Enable Developer Options -> USB Debugging on Android.",
                "On Windows, verify Android Bootloader / ADB USB drivers in Device Manager.",
            ],
            StatusSeverity::Error,
            false,
        ),
        "NO_WPD_DEVICES" => (
            "NO_WPD_DEVICES".to_string(),
            "No Windows Portable Devices (WPD/MTP) portable devices were detected.",
            vec![
                "Connect the Android device via USB and select 'File Transfer (MTP)' in the USB notification.",
                "Unlock the device screen or provide an offline synthetic directory fixture via --source-dir.",
            ],
            StatusSeverity::Error,
            false,
        ),
        "WPD_ACCESS_DENIED" => (
            "WPD_ACCESS_DENIED".to_string(),
            "Access denied by WPD/MTP portable device.",
            vec!["Unlock the Android device screen and confirm MTP file transfer permission."],
            StatusSeverity::Error,
            false,
        ),
        "WPD_UNSUPPORTED_PLATFORM" => (
            "WPD_UNSUPPORTED_PLATFORM".to_string(),
            "Live WPD COM device enumeration is only supported on Windows.",
            vec![
                "Pass --source-dir <fixture_dir> to search an offline synthetic MTP directory tree on non-Windows hosts.",
            ],
            StatusSeverity::Error,
            false,
        ),
        "INSTALL_FAILED_ALREADY_EXISTS" => (
            upper.clone(),
            "Package is already installed on the device.",
            vec!["Re-run `adb install` with `-r` (reinstall preserving data)."],
            StatusSeverity::Warning,
            false,
        ),
        "INSTALL_FAILED_VERSION_DOWNGRADE" => (
            upper.clone(),
            "Installed app has a higher versionCode than the APK being installed.",
            vec!["Add `-d` (allow downgrade, debuggable builds) or uninstall existing app first."],
            StatusSeverity::Error,
            false,
        ),
        "INSTALL_FAILED_UPDATE_INCOMPATIBLE" => (
            upper.clone(),
            "Signing certificate of the new APK does not match the installed package.",
            vec!["Uninstall the existing package before installing a differently signed APK."],
            StatusSeverity::Error,
            false,
        ),
        "INSTALL_FAILED_INSUFFICIENT_STORAGE" => (
            upper.clone(),
            "Target /data partition lacks free storage for APK installation.",
            vec!["Free space on /data or clear app caches before retrying."],
            StatusSeverity::Error,
            false,
        ),
        "INSTALL_FAILED_OLDER_SDK" => (
            upper.clone(),
            "Device Android API level is lower than APK android:minSdkVersion.",
            vec!["Deploy to a newer Android OS image or adjust minSdkVersion."],
            StatusSeverity::Error,
            false,
        ),
        "INSTALL_PARSE_FAILED_NO_CERTIFICATES" => (
            upper.clone(),
            "APK has no valid v1/v2/v3/v4 cryptographic signature.",
            vec!["Sign the APK with `apksigner` before installing."],
            StatusSeverity::Error,
            false,
        ),
        "INSTALL_FAILED_USER_RESTRICTED" => (
            upper.clone(),
            "Installation blocked by user/MDM policy or MIUI/OEM USB install toggle.",
            vec!["Enable 'Install via USB' in Developer Options or check device policy."],
            StatusSeverity::Error,
            false,
        ),
        "DELETE_FAILED_INTERNAL_ERROR" | "DELETE_FAILED_DEVICE_POLICY_MANAGER" => (
            upper.clone(),
            "Package could not be uninstalled (system app or active Device Admin / Owner).",
            vec![
                "For system bloatware on non-root devices, use `adb shell pm disable-user --user 0 <pkg>`.",
                "Revoke Device Admin privileges in Settings -> Security before uninstalling.",
            ],
            StatusSeverity::Error,
            false,
        ),
        "FASTBOOT_LOCKED" | "FAILED_REMOTE_FLASHING_NOT_ALLOWED" => (
            upper.clone(),
            "Bootloader is locked; flashing or erasing protected partitions is blocked.",
            vec![
                "Enable 'OEM unlocking' in Developer Options, then carefully evaluate `fastboot flashing unlock` (wipes userdata).",
            ],
            StatusSeverity::Fatal,
            false,
        ),
        "FASTBOOT_PARTITION_NOT_FOUND" => (
            upper.clone(),
            "Specified partition name does not exist in device partition table / current A/B slot.",
            vec![
                "Run `fastboot getvar all` to list valid partitions and `current-slot` (_a / _b).",
                "Dynamic partitions (`system`, `vendor`, `product`) require userspace `fastbootd` (`adb reboot fastboot`).",
            ],
            StatusSeverity::Error,
            false,
        ),
        _ => (
            if trimmed.is_empty() {
                "UNKNOWN".to_string()
            } else {
                upper
            },
            "Unrecognized status token. Inspect raw ADB/Fastboot output for full device message.",
            vec!["Verify exact error string from `adb` or `fastboot` stderr."],
            StatusSeverity::Warning,
            false,
        ),
    };

    StatusCodeInfo {
        code: trimmed.to_string(),
        exit_code: None,
        severity: sev,
        is_success: ok,
        short_label: label,
        summary: summary.to_string(),
        details: details.into_iter().map(str::to_string).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_numeric_and_android_status_codes() {
        let ok = decode_status_code("0");
        assert!(ok.is_success);
        assert_eq!(ok.exit_code, Some(0));

        let unauth = decode_status_code("device_unauthorized");
        assert!(!unauth.is_success);
        assert_eq!(unauth.short_label, "DEVICE_UNAUTHORIZED");

        let downgrade = decode_status_code("INSTALL_FAILED_VERSION_DOWNGRADE");
        assert_eq!(downgrade.severity, StatusSeverity::Error);
        assert!(downgrade.details[0].contains("-d"));
    }
}
