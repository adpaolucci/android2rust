use crate::app::App;
use crate::message::Message;
use crate::views::{page_header, section_card};
use android2rust_core::RebootTarget;
use iced::widget::{button, checkbox, column, pick_list, row, scrollable, text, text_input};
use iced::{Alignment, Element, Font, Length};

pub fn view_adb_packages(app: &App) -> Element<'_, Message> {
    let p = &app.job.package_opts;
    let header = page_header(
        "ADB Packages, Permissions, Sideload & Reboot Options",
        button(text("Reset Default").size(12))
            .on_press(Message::ResetDefaultJob)
            .style(button::secondary),
    );

    let list_opts = column![
        row![
            checkbox(p.third_party_only)
                .label("-3 (Third-party packages only)")
                .on_toggle(Message::ToggleThirdPartyOnly),
            checkbox(p.system_only)
                .label("-s (System packages only)")
                .on_toggle(Message::ToggleSystemOnly),
            checkbox(p.show_apk_path)
                .label("-f (Show APK path)")
                .on_toggle(Message::ToggleShowApkPath),
            checkbox(p.show_installer)
                .label("-i (Show installer)")
                .on_toggle(Message::ToggleShowInstaller),
            checkbox(p.show_uid)
                .label("-U (Show UID)")
                .on_toggle(Message::ToggleShowUid),
        ]
        .spacing(12),
    ]
    .spacing(8);

    let install_opts = column![
        row![
            checkbox(p.reinstall)
                .label("-r (Reinstall keeping data)")
                .on_toggle(Message::ToggleReinstall),
            checkbox(p.allow_downgrade)
                .label("-d (Allow version downgrade)")
                .on_toggle(Message::ToggleAllowDowngrade),
            checkbox(p.grant_permissions)
                .label("-g (Grant runtime permissions)")
                .on_toggle(Message::ToggleGrantPerms),
            checkbox(p.keep_data)
                .label("-k (Keep data on uninstall)")
                .on_toggle(Message::ToggleKeepData),
        ]
        .spacing(12),
        row![
            text("Android User ID (--user):").size(13),
            text_input("0", &app.user_id_text)
                .on_input(Message::UserIdChanged)
                .size(13)
                .width(Length::Fixed(80.0)),
            text("Reboot Target:").size(13),
            pick_list(
                [
                    RebootTarget::System,
                    RebootTarget::Bootloader,
                    RebootTarget::Recovery,
                    RebootTarget::Fastbootd,
                    RebootTarget::Sideload,
                ],
                Some(app.job.reboot_target),
                Message::RebootTargetChanged,
            )
            .text_size(13),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    ]
    .spacing(8);

    scrollable(
        column![
            header,
            section_card("Package Enumeration Flags (adb shell pm list packages)", list_opts),
            section_card("APK Install / Uninstall / User Target Options", install_opts),
        ]
        .spacing(12),
    )
    .height(Length::Fill)
    .into()
}

pub fn view_transfer_logcat(app: &App) -> Element<'_, Message> {
    let t = &app.job.transfer_opts;
    let b = &app.job.backup_opts;
    let l = &app.job.logcat_opts;

    let header = page_header(
        "File Transfer, Android Backup (.ab) & Logcat Options",
        text("ADB Pull / Push / Backup / Logcat").size(12),
    );

    let transfer_card = row![
        checkbox(t.preserve_timestamps)
            .label("-a (Preserve timestamps/mode on pull)")
            .on_toggle(Message::TogglePreserveTimestamps),
        checkbox(t.sync_only_newer)
            .label("--sync (Push only newer files)")
            .on_toggle(Message::ToggleSyncNewer),
        text("Compression (-z):").size(13),
        text_input("any | brotli | lz4 | zstd", t.compression.as_deref().unwrap_or(""))
            .on_input(Message::CompressionChanged)
            .size(13)
            .width(Length::Fixed(180.0)),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let backup_card = column![
        row![
            checkbox(b.include_apk)
                .label("-apk (Include APKs)")
                .on_toggle(Message::ToggleBackupApk),
            checkbox(b.include_obb)
                .label("-obb (Include OBBs)")
                .on_toggle(Message::ToggleBackupObb),
            checkbox(b.include_shared)
                .label("-shared (Shared storage)")
                .on_toggle(Message::ToggleBackupShared),
            checkbox(b.all_apps)
                .label("-all (All apps)")
                .on_toggle(Message::ToggleBackupAll),
            checkbox(b.include_system)
                .label("-system (System apps)")
                .on_toggle(Message::ToggleBackupSystem),
        ]
        .spacing(12),
        row![
            text("Explicit Packages:").size(13),
            text_input("com.example.one com.example.two", &app.backup_packages_text)
                .on_input(Message::BackupPackagesChanged)
                .font(Font::MONOSPACE)
                .size(12)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(8);

    let logcat_card = column![
        row![
            text("Buffers (-b):").size(13),
            text_input("main system crash", &app.logcat_buffers_text)
                .on_input(Message::LogcatBuffersChanged)
                .font(Font::MONOSPACE)
                .size(12)
                .width(Length::Fixed(220.0)),
            text("Format (-v):").size(13),
            text_input("threadtime", &l.format)
                .on_input(Message::LogcatFormatChanged)
                .font(Font::MONOSPACE)
                .size(12)
                .width(Length::Fixed(120.0)),
            text("Max Lines (-t):").size(13),
            text_input("500", &app.logcat_max_lines_text)
                .on_input(Message::LogcatMaxLinesChanged)
                .size(13)
                .width(Length::Fixed(80.0)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            checkbox(l.dump_and_exit)
                .label("-d (Dump current buffer and exit)")
                .on_toggle(Message::ToggleLogcatDump),
            checkbox(l.clear_first)
                .label("-c (Clear buffer first)")
                .on_toggle(Message::ToggleLogcatClear),
        ]
        .spacing(14),
        row![
            text("Filter Specs:").size(13),
            text_input("ActivityManager:I AndroidRuntime:E *:S", &app.logcat_filters_text)
                .on_input(Message::LogcatFiltersChanged)
                .font(Font::MONOSPACE)
                .size(12)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(8);

    scrollable(
        column![
            header,
            section_card("ADB Pull / Push Options", transfer_card),
            section_card("ADB Backup (.ab) Options", backup_card),
            section_card("Logcat Capture Options", logcat_card),
        ]
        .spacing(12),
    )
    .height(Length::Fill)
    .into()
}

pub fn view_fastboot_partitions(app: &App) -> Element<'_, Message> {
    let fb = &app.job.fastboot_opts;
    let header = page_header(
        "Fastboot Partition Flashing, Slot Targeting & Bootloader Controls",
        text("Guarded Destructive Operations").size(12),
    );

    let card = column![
        row![
            text("Target Partition:").size(13),
            text_input("boot / init_boot / recovery / vbmeta", &fb.partition)
                .on_input(Message::PartitionChanged)
                .font(Font::MONOSPACE)
                .size(13)
                .width(Length::Fixed(240.0)),
            text("A/B Slot (--slot):").size(13),
            text_input("a | b | all", fb.slot.as_deref().unwrap_or(""))
                .on_input(Message::SlotChanged)
                .font(Font::MONOSPACE)
                .size(13)
                .width(Length::Fixed(100.0)),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
        row![
            checkbox(fb.skip_reboot)
                .label("--skip-reboot")
                .on_toggle(Message::ToggleSkipReboot),
            checkbox(fb.wipe_userdata)
                .label("-w (Wipe userdata & cache — DESTRUCTIVE)")
                .on_toggle(Message::ToggleWipeUserdata),
            checkbox(fb.disable_verity)
                .label("--disable-verity")
                .on_toggle(Message::ToggleDisableVerity),
            checkbox(fb.disable_verification)
                .label("--disable-verification")
                .on_toggle(Message::ToggleDisableVerification),
        ]
        .spacing(12),
    ]
    .spacing(10);

    scrollable(column![header, section_card("Fastboot Flags", card)].spacing(12))
        .height(Length::Fill)
        .into()
}

pub fn view_forensics_artifacts(app: &App) -> Element<'_, Message> {
    let f = &app.job.forensic_opts;
    let header = page_header(
        "Pure-Rust Offline Android Forensics & Case Provenance",
        button(text("Run Offline Inspection Now").size(12))
            .on_press(Message::RunOfflineInspectionNow)
            .style(button::primary),
    );

    let card = column![
        text("Zero external dependencies: inspects .apk (AXML security flags, v1/v2/v3/v3.1 signatures, Janus & Zip-Slip), .ab backups (plain or PBKDF2/AES-256-CBC decrypted), Android 12+ ABX, adb bugreport .zip dumps, SQLite 3 schemas/freelist/WAL companions, shared_prefs XMLs, and extracted directories.").size(13),
        row![
            checkbox(f.compute_sha256)
                .label("Compute dual SHA-256 & SHA-512 chain-of-custody digests")
                .on_toggle(Message::ToggleForensicSha256),
            checkbox(f.extract_manifest_permissions)
                .label("Extract AndroidManifest.xml permissions")
                .on_toggle(Message::ToggleForensicPerms),
        ]
        .spacing(16),
        row![
            checkbox(f.inspect_sqlite_tables)
                .label("Scan SQLite 3 tables, freelist & -wal/-shm/-journal companions")
                .on_toggle(Message::ToggleForensicSqlite),
            checkbox(f.inspect_ab_tar_entries)
                .label("Decompress / decrypt .ab backup & list TAR entries")
                .on_toggle(Message::ToggleForensicTar),
        ]
        .spacing(16),
        row![
            text("Max Entries:").size(13),
            text_input("2000", &app.forensic_max_entries_text)
                .on_input(Message::ForensicMaxEntriesChanged)
                .size(13)
                .width(Length::Fixed(90.0)),
            text("Extra CLI Args:").size(13),
            text_input("Optional raw flags", &app.extra_args_text)
                .on_input(Message::ExtraArgsChanged)
                .font(Font::MONOSPACE)
                .size(12)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(10);

    let prov_card = column![
        row![
            text("Case ID:").size(13),
            text_input("e.g. IR-2026-04", f.case_meta.case_id.as_deref().unwrap_or(""))
                .on_input(Message::CaseIdChanged)
                .size(13)
                .width(Length::Fill),
            text("Evidence ID:").size(13),
            text_input("e.g. EV-01", f.case_meta.evidence_id.as_deref().unwrap_or(""))
                .on_input(Message::EvidenceIdChanged)
                .size(13)
                .width(Length::Fill),
            text("Examiner:").size(13),
            text_input("Examiner name", f.case_meta.examiner.as_deref().unwrap_or(""))
                .on_input(Message::ExaminerChanged)
                .size(13)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            text(".ab Passphrase (RAM only):").size(13),
            text_input(
                "Optional passphrase to decrypt encrypted .ab backup",
                f.ab_password.as_deref().unwrap_or(""),
            )
            .on_input(Message::AbPasswordChanged)
            .secure(true)
            .size(13)
            .width(Length::Fixed(320.0)),
            text("Never serialized to .a2r recipes, profiles.json, or JSON reports.").size(12),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(10);

    scrollable(
        column![
            header,
            section_card("Offline Forensic Engine Settings", card),
            section_card("Case Provenance & Encrypted .ab Decryption", prov_card),
        ]
        .spacing(12),
    )
    .height(Length::Fill)
    .into()
}
