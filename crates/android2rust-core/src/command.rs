use crate::model::{AndroidJob, AndroidOperation, ToolFamily, TransportMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleCadence {
    Daily,
    Weekly,
    Hourly,
    OnStart,
    OnLogon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleSpec {
    pub cadence: ScheduleCadence,
    pub start_time: String,
    pub days: Option<String>,
    pub run_highest: bool,
}

impl Default for ScheduleSpec {
    fn default() -> Self {
        Self {
            cadence: ScheduleCadence::Daily,
            start_time: "02:00".to_string(),
            days: None,
            run_highest: true,
        }
    }
}

/// Quotes an argument safely for Windows `CommandLineToArgvW` and `cmd.exe`,
/// doubling trailing backslashes immediately before the closing quote (`C:\` -> `"C:\\"`).
pub fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quotes = arg.chars().any(|c| {
        matches!(
            c,
            ' ' | '\t' | '"' | '&' | '|' | '<' | '>' | '^' | '(' | ')' | ';' | ',' | '%' | '!'
        )
    }) || arg.ends_with('\\');

    if !needs_quotes {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 4);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            out.push(ch);
            backslashes = 0;
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

pub fn quote_posix_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '=' | ',' | '@'))
    {
        return arg.to_string();
    }
    let escaped = arg.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

/// Builds `(binary_name, arguments)` for the given [`AndroidJob`].
pub fn build_args(job: &AndroidJob) -> (String, Vec<String>) {
    let tool = if job.operation == AndroidOperation::InspectArtifact {
        ToolFamily::Forensics
    } else if job.operation.default_tool() != job.tool {
        job.operation.default_tool()
    } else {
        job.tool
    };

    let mut args = Vec::new();

    match tool {
        ToolFamily::Adb => {
            match job.effective_transport() {
                TransportMode::Auto => {}
                TransportMode::Usb => args.push("-d".to_string()),
                TransportMode::Emulator => args.push("-e".to_string()),
                TransportMode::Serial(s) if !s.trim().is_empty() => {
                    args.push("-s".to_string());
                    args.push(s.trim().to_string());
                }
                TransportMode::Serial(_) => {}
                TransportMode::TransportId(id) => {
                    args.push("-t".to_string());
                    args.push(id.to_string());
                }
            }
            build_adb_subargs(job, &mut args);
        }
        ToolFamily::Fastboot => {
            if let TransportMode::Serial(s) = job.effective_transport()
                && !s.trim().is_empty()
            {
                args.push("-s".to_string());
                args.push(s.trim().to_string());
            }
            build_fastboot_subargs(job, &mut args);
        }
        ToolFamily::Forensics => {
            args.push("inspect".to_string());
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
            if !job.target_path.trim().is_empty() {
                args.push("--report".to_string());
                args.push(job.target_path.trim().to_string());
            }
            if let Some(cid) = job
                .forensic_opts
                .case_meta
                .case_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                args.push("--case-id".to_string());
                args.push(cid.to_string());
            }
            if let Some(eid) = job
                .forensic_opts
                .case_meta
                .evidence_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                args.push("--evidence-id".to_string());
                args.push(eid.to_string());
            }
            if let Some(ex) = job
                .forensic_opts
                .case_meta
                .examiner
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                args.push("--examiner".to_string());
                args.push(ex.to_string());
            }
            for extra in &job.extra_args {
                let t = extra.trim();
                if !t.is_empty() {
                    args.push(t.to_string());
                }
            }
            return ("android2rust".to_string(), args);
        }
    }

    for extra in &job.extra_args {
        let t = extra.trim();
        if !t.is_empty() {
            args.push(t.to_string());
        }
    }

    (tool.binary_name().to_string(), args)
}

fn build_adb_subargs(job: &AndroidJob, args: &mut Vec<String>) {
    match job.operation {
        AndroidOperation::Devices => {
            args.push("devices".to_string());
            args.push("-l".to_string());
        }
        AndroidOperation::DeviceProps => {
            args.push("shell".to_string());
            args.push("getprop".to_string());
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::Packages => {
            args.push("shell".to_string());
            args.push("pm".to_string());
            args.push("list".to_string());
            args.push("packages".to_string());
            if job.package_opts.third_party_only {
                args.push("-3".to_string());
            } else if job.package_opts.system_only {
                args.push("-s".to_string());
            }
            if job.package_opts.show_apk_path {
                args.push("-f".to_string());
            }
            if job.package_opts.show_installer {
                args.push("-i".to_string());
            }
            if job.package_opts.show_uid {
                args.push("-U".to_string());
            }
            if let Some(u) = job.package_opts.user_id {
                args.push("--user".to_string());
                args.push(u.to_string());
            }
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::InstallApk => {
            args.push("install".to_string());
            if job.package_opts.reinstall {
                args.push("-r".to_string());
            }
            if job.package_opts.allow_downgrade {
                args.push("-d".to_string());
            }
            if job.package_opts.grant_permissions {
                args.push("-g".to_string());
            }
            if let Some(u) = job.package_opts.user_id {
                args.push("--user".to_string());
                args.push(u.to_string());
            }
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
        }
        AndroidOperation::UninstallPackage => {
            args.push("uninstall".to_string());
            if job.package_opts.keep_data {
                args.push("-k".to_string());
            }
            if let Some(u) = job.package_opts.user_id {
                args.push("--user".to_string());
                args.push(u.to_string());
            }
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::DisablePackage => {
            args.push("shell".to_string());
            args.push("pm".to_string());
            args.push("disable-user".to_string());
            args.push("--user".to_string());
            args.push(job.package_opts.user_id.unwrap_or(0).to_string());
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::EnablePackage => {
            args.push("shell".to_string());
            args.push("pm".to_string());
            args.push("enable".to_string());
            if let Some(u) = job.package_opts.user_id {
                args.push("--user".to_string());
                args.push(u.to_string());
            }
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::Pull => {
            args.push("pull".to_string());
            if job.transfer_opts.preserve_timestamps {
                args.push("-a".to_string());
            }
            if let Some(algo) = &job.transfer_opts.compression
                && !algo.trim().is_empty()
            {
                args.push("-z".to_string());
                args.push(algo.trim().to_string());
            }
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::Push => {
            args.push("push".to_string());
            if job.transfer_opts.sync_only_newer {
                args.push("--sync".to_string());
            }
            if let Some(algo) = &job.transfer_opts.compression
                && !algo.trim().is_empty()
            {
                args.push("-z".to_string());
                args.push(algo.trim().to_string());
            }
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::BackupAb => {
            args.push("backup".to_string());
            let out_file = if job.target_path.trim().is_empty() {
                "backup.ab"
            } else {
                job.target_path.trim()
            };
            args.push("-f".to_string());
            args.push(out_file.to_string());
            args.push(if job.backup_opts.include_apk { "-apk" } else { "-noapk" }.to_string());
            args.push(if job.backup_opts.include_obb { "-obb" } else { "-noobb" }.to_string());
            args.push(
                if job.backup_opts.include_shared {
                    "-shared"
                } else {
                    "-noshared"
                }
                .to_string(),
            );
            if job.backup_opts.all_apps {
                args.push("-all".to_string());
            }
            args.push(
                if job.backup_opts.include_system {
                    "-system"
                } else {
                    "-nosystem"
                }
                .to_string(),
            );
            for pkg in &job.backup_opts.packages {
                let p = pkg.trim();
                if !p.is_empty() {
                    args.push(p.to_string());
                }
            }
        }
        AndroidOperation::RestoreAb => {
            args.push("restore".to_string());
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
        }
        AndroidOperation::Bugreport => {
            args.push("bugreport".to_string());
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::Logcat => {
            args.push("logcat".to_string());
            for buf in &job.logcat_opts.buffers {
                let b = buf.trim();
                if !b.is_empty() {
                    args.push("-b".to_string());
                    args.push(b.to_string());
                }
            }
            if !job.logcat_opts.format.trim().is_empty() {
                args.push("-v".to_string());
                args.push(job.logcat_opts.format.trim().to_string());
            }
            if job.logcat_opts.clear_first {
                args.push("-c".to_string());
            }
            if job.logcat_opts.dump_and_exit {
                args.push("-d".to_string());
            }
            if let Some(n) = job.logcat_opts.max_lines {
                args.push("-t".to_string());
                args.push(n.to_string());
            }
            for spec in &job.logcat_opts.filter_specs {
                let s = spec.trim();
                if !s.is_empty() {
                    args.push(s.to_string());
                }
            }
        }
        AndroidOperation::Dumpsys => {
            args.push("shell".to_string());
            args.push("dumpsys".to_string());
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::Shell => {
            args.push("shell".to_string());
            if !job.target_path.trim().is_empty() {
                args.push(job.target_path.trim().to_string());
            }
        }
        AndroidOperation::Sideload => {
            args.push("sideload".to_string());
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
        }
        AndroidOperation::Reboot => {
            args.push("reboot".to_string());
            if let Some(t) = job.reboot_target.as_arg() {
                args.push(t.to_string());
            }
        }
        _ => {}
    }
}

fn build_fastboot_subargs(job: &AndroidJob, args: &mut Vec<String>) {
    if job.fastboot_opts.skip_reboot
        && matches!(
            job.operation,
            AndroidOperation::FastbootFlash | AndroidOperation::FastbootErase | AndroidOperation::FastbootFormat
        )
    {
        args.push("--skip-reboot".to_string());
    }
    if job.fastboot_opts.disable_verity && job.operation == AndroidOperation::FastbootFlash {
        args.push("--disable-verity".to_string());
    }
    if job.fastboot_opts.disable_verification && job.operation == AndroidOperation::FastbootFlash {
        args.push("--disable-verification".to_string());
    }
    if let Some(slot) = &job.fastboot_opts.slot
        && !slot.trim().is_empty()
        && matches!(
            job.operation,
            AndroidOperation::FastbootFlash
                | AndroidOperation::FastbootErase
                | AndroidOperation::FastbootFormat
                | AndroidOperation::FastbootGetvar
        )
    {
        args.push("--slot".to_string());
        args.push(slot.trim().to_string());
    }
    if job.fastboot_opts.wipe_userdata
        && matches!(
            job.operation,
            AndroidOperation::FastbootFlash | AndroidOperation::FastbootErase | AndroidOperation::FastbootFormat
        )
    {
        args.push("-w".to_string());
    }

    match job.operation {
        AndroidOperation::FastbootDevices => args.push("devices".to_string()),
        AndroidOperation::FastbootGetvar => {
            args.push("getvar".to_string());
            let var = if job.target_path.trim().is_empty() {
                "all"
            } else {
                job.target_path.trim()
            };
            args.push(var.to_string());
        }
        AndroidOperation::FastbootFlash => {
            args.push("flash".to_string());
            let part = if !job.fastboot_opts.partition.trim().is_empty() {
                job.fastboot_opts.partition.trim()
            } else {
                job.target_path.trim()
            };
            if !part.is_empty() {
                args.push(part.to_string());
            }
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
        }
        AndroidOperation::FastbootBoot => {
            args.push("boot".to_string());
            if !job.source_path.trim().is_empty() {
                args.push(job.source_path.trim().to_string());
            }
        }
        AndroidOperation::FastbootErase => {
            args.push("erase".to_string());
            let part = if !job.fastboot_opts.partition.trim().is_empty() {
                job.fastboot_opts.partition.trim()
            } else {
                job.target_path.trim()
            };
            if !part.is_empty() {
                args.push(part.to_string());
            }
        }
        AndroidOperation::FastbootFormat => {
            args.push("format".to_string());
            let part = if !job.fastboot_opts.partition.trim().is_empty() {
                job.fastboot_opts.partition.trim()
            } else {
                job.target_path.trim()
            };
            if !part.is_empty() {
                args.push(part.to_string());
            }
        }
        AndroidOperation::FastbootFlashingUnlock => {
            args.push("flashing".to_string());
            args.push("unlock".to_string());
        }
        AndroidOperation::FastbootFlashingLock => {
            args.push("flashing".to_string());
            args.push("lock".to_string());
        }
        AndroidOperation::FastbootReboot => {
            args.push("reboot".to_string());
            if let Some(t) = job.reboot_target.as_arg() {
                args.push(t.to_string());
            }
        }
        _ => {}
    }
}

fn sanitize_single_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

fn escape_batch_percent(s: &str) -> String {
    sanitize_single_line(s).replace('%', "%%")
}

fn escape_batch_echo(s: &str) -> String {
    let clean = sanitize_single_line(s);
    let mut out = String::with_capacity(clean.len() + 8);
    for ch in clean.chars() {
        match ch {
            '^' => out.push_str("^^"),
            '%' => out.push_str("%%"),
            '&' => out.push_str("^&"),
            '|' => out.push_str("^|"),
            '<' => out.push_str("^<"),
            '>' => out.push_str("^>"),
            '(' => out.push_str("^("),
            ')' => out.push_str("^)"),
            '"' => out.push_str("^\""),
            _ => out.push(ch),
        }
    }
    out
}

pub fn format_command_line(job: &AndroidJob) -> String {
    let (bin, args) = build_args(job);
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(bin);
    for a in args {
        parts.push(quote_windows_arg(&sanitize_single_line(&a)));
    }
    parts.join(" ")
}

pub fn build_batch_script(job: &AndroidJob) -> String {
    let cmd_line = format_command_line(job);
    let exec_cmd = escape_batch_percent(&cmd_line);
    let echo_cmd = escape_batch_echo(&cmd_line);
    let safe_name = sanitize_single_line(&job.name);
    let mut out = String::new();
    out.push_str("@echo off\r\n");
    out.push_str("setlocal EnableExtensions\r\n");
    out.push_str(&format!("rem Generated by android2rust — {safe_name}\r\n"));
    out.push_str(&format!("echo Running: {echo_cmd}\r\n"));
    out.push_str(&format!("{exec_cmd}\r\n"));
    out.push_str("set EXITCODE=%ERRORLEVEL%\r\n");
    out.push_str("echo Android2Rust exit code: %EXITCODE%\r\n");
    out.push_str("exit /b %EXITCODE%\r\n");
    out
}

pub fn build_powershell_script(job: &AndroidJob) -> String {
    let (bin, args) = build_args(job);
    let ps_args: Vec<String> = args
        .iter()
        .map(|a| format!("'{}'", sanitize_single_line(a).replace('\'', "''")))
        .collect();
    let safe_name = sanitize_single_line(&job.name).replace('\'', "''");
    let mut out = String::new();
    out.push_str("# Generated by android2rust\n");
    out.push_str("$ErrorActionPreference = 'Stop'\n");
    out.push_str(&format!("$JobName = '{safe_name}'\n"));
    out.push_str(&format!("$Tool = '{bin}'\n"));
    out.push_str(&format!("$ArgsList = @({})\n", ps_args.join(", ")));
    out.push_str("Write-Host \"[$JobName] Executing: $Tool $($ArgsList -join ' ')\"\n");
    out.push_str("& $Tool @ArgsList\n");
    out.push_str("$code = $LASTEXITCODE\n");
    out.push_str("Write-Host \"Exit code: $code\"\n");
    out.push_str("exit $code\n");
    out
}

pub fn build_shell_script(job: &AndroidJob) -> String {
    let (bin, args) = build_args(job);
    let quoted_args: Vec<String> = args.iter().map(|a| quote_posix_arg(a)).collect();
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n# Generated by android2rust — {}\n{} {}\n",
        job.name.replace(['\r', '\n'], " "),
        bin,
        quoted_args.join(" ")
    )
}

pub fn build_schtasks_command(task_name: &str, target_command_or_script: &str, spec: &ScheduleSpec) -> String {
    let clean_name = if task_name.trim().is_empty() {
        "Android2Rust_Job"
    } else {
        task_name.trim()
    };
    let clean_target = if target_command_or_script.trim().is_empty() {
        "android2rust.exe dry-run"
    } else {
        target_command_or_script.trim()
    };

    let mut args = vec![
        "schtasks".to_string(),
        "/Create".to_string(),
        "/F".to_string(),
        "/TN".to_string(),
        quote_windows_arg(clean_name),
        "/TR".to_string(),
        quote_windows_arg(clean_target),
        "/SC".to_string(),
    ];

    match spec.cadence {
        ScheduleCadence::Daily => {
            args.push("DAILY".to_string());
            args.push("/ST".to_string());
            args.push(spec.start_time.trim().to_string());
        }
        ScheduleCadence::Weekly => {
            args.push("WEEKLY".to_string());
            if let Some(d) = &spec.days
                && !d.trim().is_empty()
            {
                args.push("/D".to_string());
                args.push(d.trim().to_string());
            }
            args.push("/ST".to_string());
            args.push(spec.start_time.trim().to_string());
        }
        ScheduleCadence::Hourly => {
            args.push("HOURLY".to_string());
            args.push("/ST".to_string());
            args.push(spec.start_time.trim().to_string());
        }
        ScheduleCadence::OnStart => args.push("ONSTART".to_string()),
        ScheduleCadence::OnLogon => args.push("ONLOGON".to_string()),
    }

    if spec.run_highest {
        args.push("/RL".to_string());
        args.push("HIGHEST".to_string());
    }

    args.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_windows_trailing_backslashes() {
        assert_eq!(quote_windows_arg(r"C:\Android SDK\"), r#""C:\Android SDK\\""#);
        assert_eq!(quote_windows_arg("simple"), "simple");
    }

    #[test]
    fn builds_adb_install_and_fastboot_flash_commands() {
        let mut job = AndroidJob {
            operation: AndroidOperation::InstallApk,
            tool: ToolFamily::Adb,
            serial: "R58M123".to_string(),
            source_path: r"C:\Builds\app release.apk".to_string(),
            ..Default::default()
        };
        job.package_opts.reinstall = true;
        job.package_opts.grant_permissions = true;

        let cmd = format_command_line(&job);
        assert_eq!(cmd, r#"adb -s R58M123 install -r -g "C:\Builds\app release.apk""#);

        let mut fb = AndroidJob {
            operation: AndroidOperation::FastbootFlash,
            tool: ToolFamily::Fastboot,
            source_path: "boot.img".to_string(),
            ..Default::default()
        };
        fb.fastboot_opts.partition = "boot".to_string();
        fb.fastboot_opts.slot = Some("a".to_string());
        assert_eq!(format_command_line(&fb), "fastboot --slot a flash boot boot.img");
    }

    #[test]
    fn escapes_batch_scripts_and_gates_fastboot_and_forensic_args() {
        let mut inspect = AndroidJob {
            operation: AndroidOperation::InspectArtifact,
            tool: ToolFamily::Forensics,
            source_path: r"C:\Evidence\backup%1.ab".to_string(),
            target_path: r"C:\Out\audit & report.html".to_string(),
            ..Default::default()
        };
        inspect.forensic_opts.case_meta.case_id = Some("IR-2026".to_string());
        inspect.forensic_opts.case_meta.examiner = Some("J. Doe".to_string());
        inspect.forensic_opts.ab_password = Some("top-secret-never-printed".to_string());

        let cmd = format_command_line(&inspect);
        assert!(cmd.contains("--case-id IR-2026"));
        assert!(cmd.contains("--examiner \"J. Doe\""));
        assert!(!cmd.contains("top-secret-never-printed"));

        let bat = build_batch_script(&inspect);
        assert!(bat.contains("%%1"));
        assert!(bat.contains("echo Running: android2rust inspect ^\"C:\\Evidence\\backup%%1.ab^\" --report ^\"C:\\Out\\audit ^& report.html^\""));

        let mut fb_devs = AndroidJob {
            operation: AndroidOperation::FastbootDevices,
            tool: ToolFamily::Fastboot,
            ..Default::default()
        };
        fb_devs.fastboot_opts.wipe_userdata = true;
        fb_devs.fastboot_opts.slot = Some("a".to_string());
        assert_eq!(format_command_line(&fb_devs), "fastboot devices");

        let mut enable = AndroidJob {
            operation: AndroidOperation::EnablePackage,
            tool: ToolFamily::Adb,
            target_path: "com.example.demo".to_string(),
            ..Default::default()
        };
        enable.package_opts.user_id = Some(10);
        assert_eq!(
            format_command_line(&enable),
            "adb shell pm enable --user 10 com.example.demo"
        );
    }
}
