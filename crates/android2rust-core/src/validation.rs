use crate::model::{AndroidJob, AndroidOperation, TransportMode};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFinding {
    pub severity: ValidationSeverity,
    pub code: String,
    pub message: String,
    pub suggestion: Option<String>,
}

fn is_boot_critical_partition(part: &str) -> bool {
    matches!(
        part.to_ascii_lowercase().as_str(),
        "bootloader" | "aboot" | "xbl" | "abl" | "radio" | "modem" | "efs"
    )
}

fn warn_if_local_missing(path_str: &str, out: &mut Vec<ValidationFinding>) {
    let trimmed = path_str.trim();
    if !trimmed.is_empty() && !Path::new(trimmed).exists() {
        out.push(ValidationFinding {
            severity: ValidationSeverity::Warning,
            code: "INPUT_FILE_NOT_FOUND".to_string(),
            message: format!("Local input path '{trimmed}' does not currently exist on disk."),
            suggestion: Some("Verify file path before live execution.".to_string()),
        });
    }
}

pub fn validate_job(job: &AndroidJob) -> Vec<ValidationFinding> {
    let mut out = Vec::new();

    // Check transport conflicts
    if !job.serial.trim().is_empty() && matches!(job.transport, TransportMode::Usb | TransportMode::Emulator) {
        out.push(ValidationFinding {
            severity: ValidationSeverity::Warning,
            code: "TRANSPORT_OVERRIDE".to_string(),
            message: "Both a device serial and -d/-e transport mode are set; -d/-e overrides serial.".to_string(),
            suggestion: Some("Set transport mode to Auto when targeting a specific serial (-s).".to_string()),
        });
    }

    // Destructive notice
    if job.is_destructive() {
        out.push(ValidationFinding {
            severity: ValidationSeverity::Warning,
            code: "DESTRUCTIVE_OP".to_string(),
            message: format!(
                "Destructive Android operation: {}",
                job.destructive_reasons().join(", ")
            ),
            suggestion: Some("Run a non-destructive Dry-Run first and verify target serial/partition.".to_string()),
        });
    }

    match job.operation {
        AndroidOperation::InstallApk | AndroidOperation::Sideload | AndroidOperation::RestoreAb => {
            if job.source_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_INPUT_FILE".to_string(),
                    message: "Local package/archive path is required for this operation.".to_string(),
                    suggestion: Some("Browse or enter a valid local .apk, .zip, or .ab path.".to_string()),
                });
            } else {
                warn_if_local_missing(&job.source_path, &mut out);
            }
        }
        AndroidOperation::InspectArtifact => {
            if job.source_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_ARTIFACT".to_string(),
                    message: "Artifact file or directory path is required for offline forensic inspection.".to_string(),
                    suggestion: Some("Select an .apk, .ab backup, SQLite .db, XML, or log dump.".to_string()),
                });
            } else if !Path::new(job.source_path.trim()).exists() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Warning,
                    code: "ARTIFACT_NOT_FOUND".to_string(),
                    message: format!("Artifact path '{}' does not currently exist on disk.", job.source_path),
                    suggestion: Some("Verify path spelling or mount location before inspecting.".to_string()),
                });
            }
        }
        AndroidOperation::Push => {
            if job.source_path.trim().is_empty() || job.target_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_TRANSFER_PATHS".to_string(),
                    message: "adb push requires both a local source path and a remote destination path.".to_string(),
                    suggestion: Some("Example remote destination: /sdcard/Download/".to_string()),
                });
            } else {
                warn_if_local_missing(&job.source_path, &mut out);
            }
        }
        AndroidOperation::Pull => {
            if job.source_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_REMOTE_PATH".to_string(),
                    message: "adb pull requires a remote Android source path.".to_string(),
                    suggestion: Some("Example remote path: /sdcard/DCIM/Camera".to_string()),
                });
            }
        }
        AndroidOperation::UninstallPackage | AndroidOperation::DisablePackage | AndroidOperation::EnablePackage => {
            if job.target_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_PACKAGE_ID".to_string(),
                    message: "Android application package ID (e.g. com.example.app) is required.".to_string(),
                    suggestion: None,
                });
            }
        }
        AndroidOperation::Shell => {
            if job.target_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_SHELL_COMMAND".to_string(),
                    message: "adb shell requires a remote shell command string.".to_string(),
                    suggestion: Some("Example: wm size && getprop ro.build.version.release".to_string()),
                });
            }
        }
        AndroidOperation::BackupAb => {
            out.push(ValidationFinding {
                severity: ValidationSeverity::Info,
                code: "ADB_BACKUP_DEPRECATION".to_string(),
                message: "Android 12+ restricts `adb backup` for apps targeting API 31+ unless debuggable.".to_string(),
                suggestion: Some(
                    "Use Inspect Artifact on existing .ab backups or adb pull on accessible storage.".to_string(),
                ),
            });
            if !job.backup_opts.all_apps && job.backup_opts.packages.is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Warning,
                    code: "EMPTY_BACKUP_SCOPE".to_string(),
                    message: "Neither -all nor specific package IDs are specified for adb backup.".to_string(),
                    suggestion: Some("Enable '-all' or add at least one package name.".to_string()),
                });
            }
        }
        AndroidOperation::FastbootFlash => {
            let part = if !job.fastboot_opts.partition.trim().is_empty() {
                job.fastboot_opts.partition.trim()
            } else {
                job.target_path.trim()
            };
            if part.is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_PARTITION".to_string(),
                    message: "Target partition name is required for fastboot flash.".to_string(),
                    suggestion: Some("Specify a valid partition such as boot, init_boot, or recovery.".to_string()),
                });
            } else if is_boot_critical_partition(part) {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Warning,
                    code: "CRITICAL_PARTITION_FLASH".to_string(),
                    message: format!(
                        "Partition '{part}' is boot-critical; flashing a corrupt image can hard-brick the device."
                    ),
                    suggestion: Some(
                        "Verify SHA-256 checksum of the image and test `fastboot boot` where supported.".to_string(),
                    ),
                });
            }
            if job.source_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_IMAGE_FILE".to_string(),
                    message: "Local .img file path is required for fastboot flash.".to_string(),
                    suggestion: None,
                });
            } else {
                warn_if_local_missing(&job.source_path, &mut out);
            }
        }
        AndroidOperation::FastbootBoot => {
            if job.source_path.trim().is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_IMAGE_FILE".to_string(),
                    message: "Local kernel/boot .img path is required for fastboot boot.".to_string(),
                    suggestion: None,
                });
            } else {
                warn_if_local_missing(&job.source_path, &mut out);
            }
        }
        AndroidOperation::FastbootErase | AndroidOperation::FastbootFormat => {
            let part = if !job.fastboot_opts.partition.trim().is_empty() {
                job.fastboot_opts.partition.trim()
            } else {
                job.target_path.trim()
            };
            if part.is_empty() {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "MISSING_PARTITION".to_string(),
                    message: "Partition name is required for erase/format.".to_string(),
                    suggestion: None,
                });
            } else if is_boot_critical_partition(part) {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Warning,
                    code: "CRITICAL_PARTITION_ERASE".to_string(),
                    message: format!(
                        "Partition '{part}' is boot-critical; erasing or formatting it can render the device unbootable."
                    ),
                    suggestion: Some("Double-check partition name and keep a verified factory image ready.".to_string()),
                });
            }
        }
        AndroidOperation::MobileFileSearch => {
            if let (Some(min), Some(max)) = (job.wpd_opts.min_size, job.wpd_opts.max_size)
                && min > max
            {
                out.push(ValidationFinding {
                    severity: ValidationSeverity::Error,
                    code: "INVALID_SIZE_RANGE".to_string(),
                    message: format!("Minimum size ({min}) cannot exceed maximum size ({max})."),
                    suggestion: Some("Adjust min_size <= max_size.".to_string()),
                });
            }
            for (label, raw_opt) in [
                ("created_after", job.wpd_opts.created_after.as_deref()),
                ("created_before", job.wpd_opts.created_before.as_deref()),
                ("modified_after", job.wpd_opts.modified_after.as_deref()),
                ("modified_before", job.wpd_opts.modified_before.as_deref()),
            ] {
                if let Some(raw) = raw_opt.map(str::trim).filter(|s| !s.is_empty())
                    && chrono::DateTime::parse_from_rfc3339(raw).is_err()
                    && chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d").is_err()
                {
                    out.push(ValidationFinding {
                        severity: ValidationSeverity::Error,
                        code: "INVALID_DATE_FILTER".to_string(),
                        message: format!("Invalid {label} date filter '{raw}'; use RFC3339 or YYYY-MM-DD."),
                        suggestion: Some("Example: 2026-01-15 or 2026-01-15T00:00:00Z".to_string()),
                    });
                }
            }
            if let Some(dir) = job
                .wpd_opts
                .offline_source_dir
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                warn_if_local_missing(dir, &mut out);
            }
        }
        _ => {}
    }

    if job.operation.default_tool() == crate::model::ToolFamily::Fastboot
        && let Some(slot) = job
            .fastboot_opts
            .slot
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        && !matches!(slot.to_ascii_lowercase().as_str(), "a" | "b" | "all" | "other")
    {
        out.push(ValidationFinding {
            severity: ValidationSeverity::Warning,
            code: "INVALID_FASTBOOT_SLOT".to_string(),
            message: format!("Fastboot slot '{slot}' is unusual; expected 'a', 'b', 'all', or 'other'."),
            suggestion: Some("Set --slot to 'a', 'b', 'all', or 'other'.".to_string()),
        });
    }

    if job.package_opts.third_party_only && job.package_opts.system_only {
        out.push(ValidationFinding {
            severity: ValidationSeverity::Warning,
            code: "CONFLICTING_PKG_FILTER".to_string(),
            message: "Both third-party (-3) and system (-s) package filters are enabled; -3 takes precedence."
                .to_string(),
            suggestion: Some("Select either Third-Party Only or System Only.".to_string()),
        });
    }

    if job.dry_run {
        out.push(ValidationFinding {
            severity: ValidationSeverity::Info,
            code: "DRY_RUN_ACTIVE".to_string(),
            message: "Dry-Run pre-flight mode active: no device state will be modified.".to_string(),
            suggestion: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ToolFamily;

    #[test]
    fn flags_missing_flash_inputs_and_critical_partitions() {
        let mut job = AndroidJob {
            tool: ToolFamily::Fastboot,
            operation: AndroidOperation::FastbootFlash,
            ..Default::default()
        };
        job.fastboot_opts.partition = "bootloader".to_string();
        let findings = validate_job(&job);
        assert!(findings.iter().any(|f| f.code == "CRITICAL_PARTITION_FLASH"));
        assert!(findings.iter().any(|f| f.code == "MISSING_IMAGE_FILE"));
        assert!(findings.iter().any(|f| f.code == "DESTRUCTIVE_OP"));
    }

    #[test]
    fn warns_on_critical_erase_invalid_slot_and_missing_local_input() {
        let mut erase = AndroidJob {
            tool: ToolFamily::Fastboot,
            operation: AndroidOperation::FastbootErase,
            ..Default::default()
        };
        erase.fastboot_opts.partition = "efs".to_string();
        erase.fastboot_opts.slot = Some("c".to_string());
        let erase_findings = validate_job(&erase);
        assert!(erase_findings.iter().any(|f| f.code == "CRITICAL_PARTITION_ERASE"));
        assert!(erase_findings.iter().any(|f| f.code == "INVALID_FASTBOOT_SLOT"));

        let install = AndroidJob {
            tool: ToolFamily::Adb,
            operation: AndroidOperation::InstallApk,
            source_path: r"Z:\does_not_exist\missing_demo_12345.apk".to_string(),
            ..Default::default()
        };
        let inst_findings = validate_job(&install);
        assert!(
            inst_findings
                .iter()
                .any(|f| f.code == "INPUT_FILE_NOT_FOUND" && f.severity == ValidationSeverity::Warning)
        );
    }

    #[test]
    fn validates_wpd_size_range_and_date_filters() {
        let mut job = AndroidJob {
            tool: ToolFamily::Wpd,
            operation: AndroidOperation::MobileFileSearch,
            ..Default::default()
        };
        job.wpd_opts.min_size = Some(10_000);
        job.wpd_opts.max_size = Some(100);
        job.wpd_opts.created_after = Some("not-a-date".to_string());
        let findings = validate_job(&job);
        assert!(findings.iter().any(|f| f.code == "INVALID_SIZE_RANGE"));
        assert!(findings.iter().any(|f| f.code == "INVALID_DATE_FILTER"));
    }
}
