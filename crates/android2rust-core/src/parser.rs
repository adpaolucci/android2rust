use crate::model::{AndroidJob, AndroidOperation, RebootTarget, ToolFamily, TransportMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseResult {
    pub job: AndroidJob,
    pub unrecognized_tokens: Vec<String>,
}

/// Tokenizes a Windows/POSIX command string into arguments, respecting double & single quotes.
pub fn tokenize_windows_cmdline(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_double = false;
    let mut in_single = false;
    let mut has_token = false;

    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                current.push(ch);
            }
            has_token = true;
            continue;
        }

        if ch == '\\' {
            let mut backslashes = 1usize;
            while chars.peek() == Some(&'\\') {
                chars.next();
                backslashes += 1;
            }
            if chars.peek() == Some(&'"') {
                for _ in 0..(backslashes / 2) {
                    current.push('\\');
                }
                if backslashes % 2 == 1 {
                    chars.next();
                    current.push('"');
                }
            } else {
                for _ in 0..backslashes {
                    current.push('\\');
                }
            }
            has_token = true;
            continue;
        }

        if ch == '"' {
            in_double = !in_double;
            has_token = true;
            continue;
        }

        if !in_double && ch == '\'' {
            in_single = true;
            has_token = true;
            continue;
        }

        if !in_double && ch.is_whitespace() {
            if has_token {
                tokens.push(std::mem::take(&mut current));
                has_token = false;
            }
            continue;
        }

        current.push(ch);
        has_token = true;
    }

    if has_token {
        tokens.push(current);
    }

    tokens
}

pub fn parse_command_line(input: &str) -> ParseResult {
    let tokens = tokenize_windows_cmdline(input);
    let mut job = AndroidJob::default();
    let mut unrecognized = Vec::new();

    if tokens.is_empty() {
        return ParseResult {
            job,
            unrecognized_tokens: unrecognized,
        };
    }

    let mut idx = 0usize;
    let first_lower = tokens[0].to_ascii_lowercase();
    let is_fastboot =
        first_lower == "fastboot" || first_lower.ends_with("\\fastboot.exe") || first_lower.ends_with("/fastboot");
    let is_adb = first_lower == "adb" || first_lower.ends_with("\\adb.exe") || first_lower.ends_with("/adb");
    let is_a2r = first_lower == "android2rust"
        || first_lower.ends_with("\\android2rust.exe")
        || first_lower.ends_with("/android2rust");

    if is_fastboot {
        job.tool = ToolFamily::Fastboot;
        idx = 1;
    } else if is_adb {
        job.tool = ToolFamily::Adb;
        idx = 1;
    } else if is_a2r {
        job.tool = ToolFamily::Forensics;
        idx = 1;
    }

    // Parse global transport flags
    while idx < tokens.len() {
        match tokens[idx].as_str() {
            "-s" if idx + 1 < tokens.len() => {
                job.serial = tokens[idx + 1].clone();
                job.transport = TransportMode::Serial(job.serial.clone());
                idx += 2;
            }
            "-t" if idx + 1 < tokens.len() => {
                if let Ok(id) = tokens[idx + 1].parse::<u32>() {
                    job.transport = TransportMode::TransportId(id);
                } else {
                    unrecognized.push(tokens[idx].clone());
                }
                idx += 2;
            }
            "-d" => {
                job.transport = TransportMode::Usb;
                idx += 1;
            }
            "-e" => {
                job.transport = TransportMode::Emulator;
                idx += 1;
            }
            "--slot" if idx + 1 < tokens.len() && job.tool == ToolFamily::Fastboot => {
                job.fastboot_opts.slot = Some(tokens[idx + 1].clone());
                idx += 2;
            }
            "--skip-reboot" if job.tool == ToolFamily::Fastboot => {
                job.fastboot_opts.skip_reboot = true;
                idx += 1;
            }
            "--disable-verity" if job.tool == ToolFamily::Fastboot => {
                job.fastboot_opts.disable_verity = true;
                idx += 1;
            }
            "--disable-verification" if job.tool == ToolFamily::Fastboot => {
                job.fastboot_opts.disable_verification = true;
                idx += 1;
            }
            "-w" if job.tool == ToolFamily::Fastboot => {
                job.fastboot_opts.wipe_userdata = true;
                idx += 1;
            }
            _ => break,
        }
    }

    let sub = tokens.get(idx).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    if job.tool == ToolFamily::Forensics || sub == "inspect" {
        job.tool = ToolFamily::Forensics;
        job.operation = AndroidOperation::InspectArtifact;
        job.name = "Parsed Forensic Inspection".to_string();
        job.description = format!("Imported command: {}", job.operation.label());
        let rest = &tokens[idx.saturating_add(1)..];
        let mut r = 0;
        while r < rest.len() {
            if rest[r] == "--report" && r + 1 < rest.len() {
                job.target_path = rest[r + 1].clone();
                r += 2;
            } else if job.source_path.is_empty() && !rest[r].starts_with('-') {
                job.source_path = rest[r].clone();
                r += 1;
            } else {
                unrecognized.push(rest[r].clone());
                r += 1;
            }
        }
        return ParseResult {
            job,
            unrecognized_tokens: unrecognized,
        };
    }

    if job.tool == ToolFamily::Fastboot {
        parse_fastboot_subcommand(&tokens[idx..], &mut job, &mut unrecognized);
    } else {
        parse_adb_subcommand(&tokens[idx..], &mut job, &mut unrecognized);
    }

    job.tool = job.operation.default_tool();
    job.description = format!("Imported command: {}", job.operation.label());

    ParseResult {
        job,
        unrecognized_tokens: unrecognized,
    }
}

fn parse_adb_subcommand(rest: &[String], job: &mut AndroidJob, unrecognized: &mut Vec<String>) {
    if rest.is_empty() {
        return;
    }
    let sub = rest[0].to_ascii_lowercase();
    let tail = &rest[1..];
    match sub.as_str() {
        "devices" => {
            job.operation = AndroidOperation::Devices;
            job.name = "Parsed ADB Devices".to_string();
        }
        "install" => {
            job.operation = AndroidOperation::InstallApk;
            job.name = "Parsed APK Install".to_string();
            let mut i = 0;
            while i < tail.len() {
                match tail[i].as_str() {
                    "-r" => job.package_opts.reinstall = true,
                    "-d" => job.package_opts.allow_downgrade = true,
                    "-g" => job.package_opts.grant_permissions = true,
                    "--user" if i + 1 < tail.len() => {
                        job.package_opts.user_id = tail[i + 1].parse().ok();
                        i += 1;
                    }
                    other if !other.starts_with('-') && job.source_path.is_empty() => {
                        job.source_path = other.to_string();
                    }
                    other => unrecognized.push(other.to_string()),
                }
                i += 1;
            }
        }
        "uninstall" => {
            job.operation = AndroidOperation::UninstallPackage;
            job.name = "Parsed Package Uninstall".to_string();
            let mut i = 0;
            while i < tail.len() {
                match tail[i].as_str() {
                    "-k" => job.package_opts.keep_data = true,
                    "--user" if i + 1 < tail.len() => {
                        job.package_opts.user_id = tail[i + 1].parse().ok();
                        i += 1;
                    }
                    other if !other.starts_with('-') && job.target_path.is_empty() => {
                        job.target_path = other.to_string();
                    }
                    other => unrecognized.push(other.to_string()),
                }
                i += 1;
            }
        }
        "pull" => {
            job.operation = AndroidOperation::Pull;
            job.name = "Parsed ADB Pull".to_string();
            let mut i = 0;
            while i < tail.len() {
                match tail[i].as_str() {
                    "-a" => job.transfer_opts.preserve_timestamps = true,
                    "-z" if i + 1 < tail.len() => {
                        job.transfer_opts.compression = Some(tail[i + 1].clone());
                        i += 1;
                    }
                    other if !other.starts_with('-') => {
                        if job.source_path.is_empty() {
                            job.source_path = other.to_string();
                        } else if job.target_path.is_empty() {
                            job.target_path = other.to_string();
                        } else {
                            unrecognized.push(other.to_string());
                        }
                    }
                    other => unrecognized.push(other.to_string()),
                }
                i += 1;
            }
        }
        "push" => {
            job.operation = AndroidOperation::Push;
            job.name = "Parsed ADB Push".to_string();
            let mut i = 0;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--sync" => job.transfer_opts.sync_only_newer = true,
                    "-z" if i + 1 < tail.len() => {
                        job.transfer_opts.compression = Some(tail[i + 1].clone());
                        i += 1;
                    }
                    other if !other.starts_with('-') => {
                        if job.source_path.is_empty() {
                            job.source_path = other.to_string();
                        } else if job.target_path.is_empty() {
                            job.target_path = other.to_string();
                        } else {
                            unrecognized.push(other.to_string());
                        }
                    }
                    other => unrecognized.push(other.to_string()),
                }
                i += 1;
            }
        }
        "backup" => {
            job.operation = AndroidOperation::BackupAb;
            job.name = "Parsed ADB Backup".to_string();
            job.backup_opts.all_apps = false;
            let mut i = 0;
            while i < tail.len() {
                match tail[i].as_str() {
                    "-f" if i + 1 < tail.len() => {
                        job.target_path = tail[i + 1].clone();
                        i += 1;
                    }
                    "-apk" => job.backup_opts.include_apk = true,
                    "-noapk" => job.backup_opts.include_apk = false,
                    "-obb" => job.backup_opts.include_obb = true,
                    "-noobb" => job.backup_opts.include_obb = false,
                    "-shared" => job.backup_opts.include_shared = true,
                    "-noshared" => job.backup_opts.include_shared = false,
                    "-all" => job.backup_opts.all_apps = true,
                    "-system" => job.backup_opts.include_system = true,
                    "-nosystem" => job.backup_opts.include_system = false,
                    other if !other.starts_with('-') => job.backup_opts.packages.push(other.to_string()),
                    other => unrecognized.push(other.to_string()),
                }
                i += 1;
            }
        }
        "restore" => {
            job.operation = AndroidOperation::RestoreAb;
            job.name = "Parsed ADB Restore".to_string();
            if let Some(p) = tail.first() {
                job.source_path = p.clone();
            }
        }
        "bugreport" => {
            job.operation = AndroidOperation::Bugreport;
            job.name = "Parsed ADB Bugreport".to_string();
            if let Some(p) = tail.first() {
                job.target_path = p.clone();
            }
        }
        "logcat" => {
            job.operation = AndroidOperation::Logcat;
            job.name = "Parsed ADB Logcat".to_string();
            job.logcat_opts.buffers.clear();
            job.logcat_opts.dump_and_exit = false;
            job.logcat_opts.max_lines = None;
            let mut i = 0;
            while i < tail.len() {
                match tail[i].as_str() {
                    "-b" if i + 1 < tail.len() => {
                        job.logcat_opts.buffers.push(tail[i + 1].clone());
                        i += 1;
                    }
                    "-v" if i + 1 < tail.len() => {
                        job.logcat_opts.format = tail[i + 1].clone();
                        i += 1;
                    }
                    "-t" if i + 1 < tail.len() => {
                        job.logcat_opts.max_lines = tail[i + 1].parse().ok();
                        i += 1;
                    }
                    "-d" => job.logcat_opts.dump_and_exit = true,
                    "-c" => job.logcat_opts.clear_first = true,
                    other if !other.starts_with('-') => job.logcat_opts.filter_specs.push(other.to_string()),
                    other => unrecognized.push(other.to_string()),
                }
                i += 1;
            }
            if job.logcat_opts.buffers.is_empty() {
                job.logcat_opts.buffers = vec!["main".to_string()];
            }
        }
        "sideload" => {
            job.operation = AndroidOperation::Sideload;
            job.name = "Parsed ADB Sideload".to_string();
            if let Some(p) = tail.first() {
                job.source_path = p.clone();
            }
        }
        "reboot" => {
            job.operation = AndroidOperation::Reboot;
            job.name = "Parsed ADB Reboot".to_string();
            job.reboot_target = parse_reboot_target(tail.first().map(String::as_str));
        }
        "shell" => {
            if tail.first().map(|s| s.as_str()) == Some("getprop") {
                job.operation = AndroidOperation::DeviceProps;
                job.name = "Parsed Getprop".to_string();
                if tail.len() > 1 {
                    job.target_path = tail[1..].join(" ");
                }
            } else if tail.first().map(|s| s.as_str()) == Some("dumpsys") {
                job.operation = AndroidOperation::Dumpsys;
                job.name = "Parsed Dumpsys".to_string();
                if tail.len() > 1 {
                    job.target_path = tail[1..].join(" ");
                }
            } else if tail.len() >= 3 && tail[0] == "pm" && tail[1] == "list" && tail[2] == "packages" {
                job.operation = AndroidOperation::Packages;
                job.name = "Parsed Package List".to_string();
                let mut i = 3;
                while i < tail.len() {
                    match tail[i].as_str() {
                        "-3" => job.package_opts.third_party_only = true,
                        "-s" => job.package_opts.system_only = true,
                        "-f" => job.package_opts.show_apk_path = true,
                        "-i" => job.package_opts.show_installer = true,
                        "-U" => job.package_opts.show_uid = true,
                        "--user" if i + 1 < tail.len() => {
                            job.package_opts.user_id = tail[i + 1].parse().ok();
                            i += 1;
                        }
                        other if !other.starts_with('-') => job.target_path = other.to_string(),
                        other => unrecognized.push(other.to_string()),
                    }
                    i += 1;
                }
            } else if tail.len() >= 2 && tail[0] == "pm" && tail[1] == "disable-user" {
                job.operation = AndroidOperation::DisablePackage;
                job.name = "Parsed Disable Package".to_string();
                if let Some(last) = tail.last() {
                    job.target_path = last.clone();
                }
            } else if tail.len() >= 2 && tail[0] == "pm" && tail[1] == "enable" {
                job.operation = AndroidOperation::EnablePackage;
                job.name = "Parsed Enable Package".to_string();
                if let Some(last) = tail.last() {
                    job.target_path = last.clone();
                }
            } else {
                job.operation = AndroidOperation::Shell;
                job.name = "Parsed ADB Shell".to_string();
                job.target_path = tail.join(" ");
            }
        }
        other => unrecognized.push(other.to_string()),
    }
}

fn parse_fastboot_subcommand(rest: &[String], job: &mut AndroidJob, unrecognized: &mut Vec<String>) {
    if rest.is_empty() {
        return;
    }
    let sub = rest[0].to_ascii_lowercase();
    let tail = &rest[1..];
    match sub.as_str() {
        "devices" => {
            job.operation = AndroidOperation::FastbootDevices;
            job.name = "Parsed Fastboot Devices".to_string();
        }
        "getvar" => {
            job.operation = AndroidOperation::FastbootGetvar;
            job.name = "Parsed Fastboot Getvar".to_string();
            job.target_path = tail.first().cloned().unwrap_or_else(|| "all".to_string());
        }
        "flash" => {
            job.operation = AndroidOperation::FastbootFlash;
            job.name = "Parsed Fastboot Flash".to_string();
            if let Some(p) = tail.first() {
                job.fastboot_opts.partition = p.clone();
                job.target_path = p.clone();
            }
            if let Some(img) = tail.get(1) {
                job.source_path = img.clone();
            }
        }
        "boot" => {
            job.operation = AndroidOperation::FastbootBoot;
            job.name = "Parsed Fastboot Boot".to_string();
            if let Some(img) = tail.first() {
                job.source_path = img.clone();
            }
        }
        "erase" => {
            job.operation = AndroidOperation::FastbootErase;
            job.name = "Parsed Fastboot Erase".to_string();
            if let Some(p) = tail.first() {
                job.fastboot_opts.partition = p.clone();
                job.target_path = p.clone();
            }
        }
        "format" => {
            job.operation = AndroidOperation::FastbootFormat;
            job.name = "Parsed Fastboot Format".to_string();
            if let Some(p) = tail.first() {
                job.fastboot_opts.partition = p.clone();
                job.target_path = p.clone();
            }
        }
        "flashing" => {
            if tail.first().map(|s| s.as_str()) == Some("unlock") {
                job.operation = AndroidOperation::FastbootFlashingUnlock;
                job.name = "Parsed Bootloader Unlock".to_string();
            } else if tail.first().map(|s| s.as_str()) == Some("lock") {
                job.operation = AndroidOperation::FastbootFlashingLock;
                job.name = "Parsed Bootloader Lock".to_string();
            } else {
                unrecognized.extend(tail.iter().cloned());
            }
        }
        "reboot" => {
            job.operation = AndroidOperation::FastbootReboot;
            job.name = "Parsed Fastboot Reboot".to_string();
            job.reboot_target = parse_reboot_target(tail.first().map(String::as_str));
        }
        other => unrecognized.push(other.to_string()),
    }
}

fn parse_reboot_target(arg: Option<&str>) -> RebootTarget {
    match arg.unwrap_or("").to_ascii_lowercase().as_str() {
        "bootloader" => RebootTarget::Bootloader,
        "recovery" => RebootTarget::Recovery,
        "fastboot" | "fastbootd" => RebootTarget::Fastbootd,
        "sideload" => RebootTarget::Sideload,
        _ => RebootTarget::System,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::format_command_line;

    #[test]
    fn parses_adb_and_fastboot_roundtrips() {
        let parsed = parse_command_line(r#"adb -s ABC123 install -r -g "C:\My Apps\demo.apk""#);
        assert!(parsed.unrecognized_tokens.is_empty());
        assert_eq!(parsed.job.serial, "ABC123");
        assert_eq!(parsed.job.operation, AndroidOperation::InstallApk);
        assert_eq!(parsed.job.source_path, r"C:\My Apps\demo.apk");
        assert!(parsed.job.package_opts.reinstall);
        assert!(parsed.job.package_opts.grant_permissions);
        assert_eq!(
            format_command_line(&parsed.job),
            r#"adb -s ABC123 install -r -g "C:\My Apps\demo.apk""#
        );

        let fb = parse_command_line("fastboot --slot b flash boot boot.img");
        assert!(fb.unrecognized_tokens.is_empty());
        assert_eq!(fb.job.tool, ToolFamily::Fastboot);
        assert_eq!(fb.job.operation, AndroidOperation::FastbootFlash);
        assert!(fb.job.description.contains("fastboot flash"));
        assert!(!fb.job.description.contains("adb devices -l"));
        assert_eq!(fb.job.fastboot_opts.slot.as_deref(), Some("b"));
        assert_eq!(fb.job.source_path, "boot.img");
    }
}
