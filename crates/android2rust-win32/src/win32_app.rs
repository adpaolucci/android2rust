use crate::LaunchArgs;
use crate::win32_dialogs::{copy_to_clipboard, pick_folder, pick_open_file, pick_save_file};
use crate::win32_state::{ActionFilter, BatchStatus, Win32State, join_tokens, split_tokens};
use android2rust_core::format::{format_bytes, format_duration};
use android2rust_core::{
    AndroidJob, AndroidOperation, RebootTarget, RunHistoryEntry, ScheduleCadence, ScheduleSpec, TransportMode,
    ValidationSeverity, build_batch_script, build_powershell_script, build_schtasks_command, build_shell_script,
    decode_status_code, parse_command_line, parse_recipe, serialize_recipe,
};
use android2rust_report::{ReportFormat, write_report};
use android2rust_runner::{RunResult, RunnerEvent, spawn_job_runner};
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use winsafe::{self as w, co, gui, msg, prelude::*};

// Menu command IDs
const IDM_IMPORT_RECIPE: u16 = 4001;
const IDM_EXPORT_RECIPE: u16 = 4002;
const IDM_EXPORT_BAT: u16 = 4003;
const IDM_EXPORT_PS1: u16 = 4004;
const IDM_EXPORT_SH: u16 = 4005;
const IDM_REPORT_HTML: u16 = 4006;
const IDM_REPORT_ALL: u16 = 4007;
const IDM_EXIT: u16 = 4008;

const IDM_RESET_JOB: u16 = 4010;
const IDM_COPY_CMD: u16 = 4012;
const IDM_SAVE_PROFILE: u16 = 4013;
const IDM_QUEUE_ADD: u16 = 4014;

const IDM_DRY_RUN: u16 = 4020;
const IDM_RUN_JOB: u16 = 4021;
const IDM_STOP_JOB: u16 = 4022;

const IDM_ABOUT: u16 = 4030;

const TAB_CONSOLE_IDX: u32 = 5;

fn lbl(parent: &(impl GuiParent + 'static), text: &str, x: i32, y: i32, w_dp: i32) -> gui::Label {
    gui::Label::new(
        parent,
        gui::LabelOpts {
            text,
            position: gui::dpi(x, y),
            size: gui::dpi(w_dp, 18),
            ..Default::default()
        },
    )
}

fn edit(
    parent: &(impl GuiParent + 'static),
    x: i32,
    y: i32,
    w_dp: i32,
    h_dp: i32,
    resize: (gui::Horz, gui::Vert),
) -> gui::Edit {
    gui::Edit::new(
        parent,
        gui::EditOpts {
            position: gui::dpi(x, y),
            width: gui::dpi_x(w_dp),
            height: gui::dpi_y(h_dp),
            resize_behavior: resize,
            ..Default::default()
        },
    )
}

fn chk(parent: &(impl GuiParent + 'static), text: &str, x: i32, y: i32) -> gui::CheckBox {
    gui::CheckBox::new(
        parent,
        gui::CheckBoxOpts {
            text,
            position: gui::dpi(x, y),
            ..Default::default()
        },
    )
}

fn btn(
    parent: &(impl GuiParent + 'static),
    text: &str,
    x: i32,
    y: i32,
    w_dp: i32,
    h_dp: i32,
    resize: (gui::Horz, gui::Vert),
) -> gui::Button {
    gui::Button::new(
        parent,
        gui::ButtonOpts {
            text,
            position: gui::dpi(x, y),
            width: gui::dpi_x(w_dp),
            height: gui::dpi_y(h_dp),
            resize_behavior: resize,
            ..Default::default()
        },
    )
}

fn tab_page(parent: &(impl GuiParent + 'static)) -> gui::TabPage {
    gui::TabPage::new(
        parent,
        gui::TabPageOpts {
            class_bg_brush: gui::Brush::Color(co::COLOR::BTNFACE),
            ..Default::default()
        },
    )
}

fn move_ctrl(ctrl: &impl GuiWindow, x: i32, y: i32, w: i32, h: i32) {
    if *ctrl.hwnd() != w::HWND::NULL {
        let _ = ctrl.hwnd().SetWindowPos(
            w::HwndPlace::None,
            w::POINT::with(x, y),
            w::SIZE::with(w.max(10), h.max(10)),
            co::SWP::NOZORDER,
        );
    }
}

fn repos_ctrl(ctrl: &impl GuiWindow, x: i32, y: i32) {
    if *ctrl.hwnd() != w::HWND::NULL {
        let _ = ctrl.hwnd().SetWindowPos(
            w::HwndPlace::None,
            w::POINT::with(x, y),
            w::SIZE::default(),
            co::SWP::NOZORDER | co::SWP::NOSIZE,
        );
    }
}

#[derive(Clone)]
struct DesignerPage {
    page: gui::TabPage,
    job_name: gui::Edit,
    job_desc: gui::Edit,
    import_cmd: gui::Edit,
    btn_parse_cmd: gui::Button,
    sch_name: gui::Edit,
    sch_cadence: gui::ComboBox,
    sch_time: gui::Edit,
    sch_highest: gui::CheckBox,
    sch_preview: gui::Edit,
    btn_copy_sch: gui::Button,
    diag_list: gui::ListView,
}

impl DesignerPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(&page, "Job Name:", 10, 12, 70);
        let job_name = edit(&page, 85, 9, 260, 22, (gui::Horz::None, gui::Vert::None));
        lbl(&page, "Notes:", 360, 12, 48);
        let job_desc = edit(&page, 412, 9, 500, 22, (gui::Horz::None, gui::Vert::None));

        lbl(&page, "Import CLI:", 10, 42, 70);
        let import_cmd = edit(&page, 85, 39, 710, 22, (gui::Horz::None, gui::Vert::None));
        let btn_parse_cmd = btn(
            &page,
            "Parse && Load",
            805,
            38,
            108,
            24,
            (gui::Horz::None, gui::Vert::None),
        );

        lbl(&page, "Task Name:", 10, 74, 70);
        let sch_name = edit(&page, 85, 71, 200, 22, (gui::Horz::None, gui::Vert::None));
        lbl(&page, "Cadence:", 295, 74, 58);
        let sch_cadence = gui::ComboBox::new(
            &page,
            gui::ComboBoxOpts {
                position: gui::dpi(356, 71),
                width: gui::dpi_x(105),
                items: &["DAILY", "WEEKLY", "HOURLY", "ONSTART", "ONLOGON"],
                selected_item: Some(0),
                ..Default::default()
            },
        );
        lbl(&page, "Time:", 472, 74, 38);
        let sch_time = edit(&page, 512, 71, 65, 22, (gui::Horz::None, gui::Vert::None));
        let sch_highest = chk(&page, "/RL HIGHEST", 588, 73);
        let btn_copy_sch = btn(
            &page,
            "Copy schtasks",
            805,
            70,
            108,
            24,
            (gui::Horz::None, gui::Vert::None),
        );

        lbl(&page, "schtasks:", 10, 104, 70);
        let sch_preview = gui::Edit::new(
            &page,
            gui::EditOpts {
                position: gui::dpi(85, 101),
                width: gui::dpi_x(828),
                height: gui::dpi_y(22),
                control_style: co::ES::AUTOHSCROLL | co::ES::READONLY,
                resize_behavior: (gui::Horz::None, gui::Vert::None),
                ..Default::default()
            },
        );

        lbl(&page, "Real-Time Validation && Safety Diagnostics:", 10, 134, 280);
        let diag_list = gui::ListView::new(
            &page,
            gui::ListViewOpts {
                position: gui::dpi(10, 156),
                size: gui::dpi(903, 330),
                columns: &[
                    ("Severity", gui::dpi_x(85)),
                    ("Code", gui::dpi_x(185)),
                    ("Message", gui::dpi_x(365)),
                    ("Suggestion", gui::dpi_x(260)),
                ],
                resize_behavior: (gui::Horz::None, gui::Vert::None),
                ..Default::default()
            },
        );

        {
            let job_desc = job_desc.clone();
            let import_cmd = import_cmd.clone();
            let btn_parse_cmd = btn_parse_cmd.clone();
            let btn_copy_sch = btn_copy_sch.clone();
            let sch_preview = sch_preview.clone();
            let diag_list = diag_list.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let gap = gui::dpi_x(8);
                let bw = gui::dpi_x(108);
                let bx = (w - pad - bw).max(gui::dpi_x(400));

                move_ctrl(
                    &job_desc,
                    gui::dpi_x(412),
                    gui::dpi_y(9),
                    (w - gui::dpi_x(412) - pad).max(gui::dpi_x(120)),
                    gui::dpi_y(22),
                );
                move_ctrl(
                    &import_cmd,
                    gui::dpi_x(85),
                    gui::dpi_y(39),
                    (bx - gap - gui::dpi_x(85)).max(gui::dpi_x(120)),
                    gui::dpi_y(22),
                );
                move_ctrl(&btn_parse_cmd, bx, gui::dpi_y(38), bw, gui::dpi_y(24));
                move_ctrl(&btn_copy_sch, bx, gui::dpi_y(70), bw, gui::dpi_y(24));
                move_ctrl(
                    &sch_preview,
                    gui::dpi_x(85),
                    gui::dpi_y(101),
                    (w - gui::dpi_x(85) - pad).max(gui::dpi_x(120)),
                    gui::dpi_y(22),
                );
                move_ctrl(
                    &diag_list,
                    pad,
                    gui::dpi_y(156),
                    (w - 2 * pad).max(gui::dpi_x(200)),
                    (h - gui::dpi_y(156) - gui::dpi_y(10)).max(gui::dpi_y(80)),
                );
                Ok(())
            });
        }

        Self {
            page,
            job_name,
            job_desc,
            import_cmd,
            btn_parse_cmd,
            sch_name,
            sch_cadence,
            sch_time,
            sch_highest,
            sch_preview,
            btn_copy_sch,
            diag_list,
        }
    }
}

#[derive(Clone)]
struct AdbPackagesPage {
    page: gui::TabPage,
    third_party: gui::CheckBox,
    system_only: gui::CheckBox,
    show_apk_path: gui::CheckBox,
    show_installer: gui::CheckBox,
    show_uid: gui::CheckBox,
    reinstall: gui::CheckBox,
    allow_downgrade: gui::CheckBox,
    grant_perms: gui::CheckBox,
    keep_data: gui::CheckBox,
    user_id: gui::Edit,
    reboot_combo: gui::ComboBox,
}

impl AdbPackagesPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(&page, "Package Enumeration (pm list packages):", 10, 14, 290);
        let third_party = chk(&page, "-3 (Third-party packages only)", 20, 40);
        let system_only = chk(&page, "-s (System packages only)", 260, 40);
        let show_apk_path = chk(&page, "-f (Show APK paths)", 475, 40);
        let show_installer = chk(&page, "-i (Show installer)", 20, 68);
        let show_uid = chk(&page, "-U (Show package UIDs)", 260, 68);

        lbl(&page, "APK Install / Uninstall / Disable Options:", 10, 108, 290);
        let reinstall = chk(&page, "-r (Reinstall keeping data)", 20, 134);
        let allow_downgrade = chk(&page, "-d (Allow version downgrade)", 260, 134);
        let grant_perms = chk(&page, "-g (Auto-grant runtime permissions)", 475, 134);
        let keep_data = chk(&page, "-k (Keep data/cache on uninstall)", 20, 162);

        lbl(&page, "Android User ID (--user):", 10, 204, 155);
        let user_id = edit(&page, 170, 201, 70, 22, (gui::Horz::None, gui::Vert::None));

        lbl(&page, "Reboot Target:", 270, 204, 95);
        let reboot_combo = gui::ComboBox::new(
            &page,
            gui::ComboBoxOpts {
                position: gui::dpi(370, 201),
                width: gui::dpi_x(180),
                items: &[
                    "System OS",
                    "Bootloader",
                    "Recovery",
                    "Userspace Fastbootd",
                    "ADB Sideload",
                ],
                selected_item: Some(0),
                ..Default::default()
            },
        );

        Self {
            page,
            third_party,
            system_only,
            show_apk_path,
            show_installer,
            show_uid,
            reinstall,
            allow_downgrade,
            grant_perms,
            keep_data,
            user_id,
            reboot_combo,
        }
    }
}

#[derive(Clone)]
struct TransferLogcatPage {
    page: gui::TabPage,
    preserve_ts: gui::CheckBox,
    sync_newer: gui::CheckBox,
    compression: gui::Edit,
    bak_apk: gui::CheckBox,
    bak_obb: gui::CheckBox,
    bak_shared: gui::CheckBox,
    bak_all: gui::CheckBox,
    bak_system: gui::CheckBox,
    bak_packages: gui::Edit,
    log_buffers: gui::Edit,
    log_format: gui::Edit,
    log_max_lines: gui::Edit,
    log_dump: gui::CheckBox,
    log_clear: gui::CheckBox,
    log_filters: gui::Edit,
}

impl TransferLogcatPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(&page, "ADB Pull / Push Transfer Options:", 10, 14, 240);
        let preserve_ts = chk(&page, "-a (Preserve timestamps && mode)", 20, 40);
        let sync_newer = chk(&page, "--sync (Push only newer files)", 265, 40);
        lbl(&page, "Compression (-z):", 500, 42, 105);
        let compression = edit(&page, 610, 39, 140, 22, (gui::Horz::None, gui::Vert::None));

        lbl(&page, "ADB Backup (.ab) Options:", 10, 80, 240);
        let bak_apk = chk(&page, "-apk (Include APKs)", 20, 106);
        let bak_obb = chk(&page, "-obb (Include OBB)", 175, 106);
        let bak_shared = chk(&page, "-shared (Shared storage)", 325, 106);
        let bak_all = chk(&page, "-all (All apps)", 500, 106);
        let bak_system = chk(&page, "-system (Include system)", 625, 106);
        lbl(&page, "Backup Packages:", 20, 138, 115);
        let bak_packages = edit(&page, 140, 135, 620, 22, (gui::Horz::None, gui::Vert::None));

        lbl(&page, "ADB Logcat Capture Options:", 10, 176, 240);
        lbl(&page, "Buffers (-b):", 20, 206, 85);
        let log_buffers = edit(&page, 110, 203, 210, 22, (gui::Horz::None, gui::Vert::None));
        lbl(&page, "Format (-v):", 335, 206, 80);
        let log_format = edit(&page, 420, 203, 120, 22, (gui::Horz::None, gui::Vert::None));
        lbl(&page, "Max Lines (-t):", 555, 206, 95);
        let log_max_lines = edit(&page, 655, 203, 95, 22, (gui::Horz::None, gui::Vert::None));

        let log_dump = chk(&page, "-d (Dump and exit)", 20, 238);
        let log_clear = chk(&page, "-c (Clear log buffer first)", 195, 238);
        lbl(&page, "Filter Specs:", 20, 270, 85);
        let log_filters = edit(&page, 110, 267, 650, 22, (gui::Horz::None, gui::Vert::None));

        Self {
            page,
            preserve_ts,
            sync_newer,
            compression,
            bak_apk,
            bak_obb,
            bak_shared,
            bak_all,
            bak_system,
            bak_packages,
            log_buffers,
            log_format,
            log_max_lines,
            log_dump,
            log_clear,
            log_filters,
        }
    }
}

#[derive(Clone)]
struct FastbootPage {
    page: gui::TabPage,
    partition: gui::Edit,
    slot: gui::Edit,
    skip_reboot: gui::CheckBox,
    wipe_userdata: gui::CheckBox,
    disable_verity: gui::CheckBox,
    disable_verification: gui::CheckBox,
}

impl FastbootPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(
            &page,
            "Target Partition (boot, init_boot, recovery, vbmeta):",
            10,
            16,
            330,
        );
        let partition = edit(&page, 350, 13, 220, 22, (gui::Horz::None, gui::Vert::None));
        lbl(&page, "A/B Slot (--slot):", 590, 16, 105);
        let slot = edit(&page, 700, 13, 90, 22, (gui::Horz::None, gui::Vert::None));

        let skip_reboot = chk(&page, "--skip-reboot (Stay in fastboot after operation)", 20, 52);
        let wipe_userdata = chk(&page, "-w (Wipe userdata && cache — DESTRUCTIVE)", 20, 82);
        let disable_verity = chk(&page, "--disable-verity (Disable dm-verity on vbmeta)", 20, 112);
        let disable_verification = chk(&page, "--disable-verification (Disable AVB verification)", 20, 142);

        Self {
            page,
            partition,
            slot,
            skip_reboot,
            wipe_userdata,
            disable_verity,
            disable_verification,
        }
    }
}

#[derive(Clone)]
struct ForensicsPage {
    page: gui::TabPage,
    sha256: gui::CheckBox,
    manifest_perms: gui::CheckBox,
    sqlite_tables: gui::CheckBox,
    ab_tar: gui::CheckBox,
    max_entries: gui::Edit,
    extra_args: gui::Edit,
}

impl ForensicsPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        lbl(
            &page,
            "Pure-Rust Offline Forensics (APK / .ab Backup / SQLite .db / XML / Directory):",
            10,
            14,
            550,
        );
        let sha256 = chk(&page, "Compute SHA-256 Chain-of-Custody Hash", 20, 42);
        let manifest_perms = chk(&page, "Extract AndroidManifest.xml Permissions from APK/XML", 20, 72);
        let sqlite_tables = chk(&page, "Scan SQLite 3 Header, WAL Flag && CREATE TABLE Schemas", 20, 102);
        let ab_tar = chk(&page, "Decompress Unencrypted .ab Backup && List TAR Entries", 20, 132);

        lbl(&page, "Max Entries:", 20, 172, 90);
        let max_entries = edit(&page, 115, 169, 95, 22, (gui::Horz::None, gui::Vert::None));
        lbl(&page, "Extra Raw CLI Args:", 235, 172, 130);
        let extra_args = edit(&page, 370, 169, 440, 22, (gui::Horz::None, gui::Vert::None));

        Self {
            page,
            sha256,
            manifest_perms,
            sqlite_tables,
            ab_tar,
            max_entries,
            extra_args,
        }
    }
}

#[derive(Clone)]
struct ConsolePage {
    page: gui::TabPage,
    progress: gui::ProgressBar,
    summary_lbl: gui::Label,
    filter_combo: gui::ComboBox,
    btn_copy_log: gui::Button,
    btn_export_html: gui::Button,
    btn_export_all: gui::Button,
    actions_list: gui::ListView,
    raw_log_edit: gui::Edit,
}

impl ConsolePage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        let progress = gui::ProgressBar::new(
            &page,
            gui::ProgressBarOpts {
                position: gui::dpi(10, 10),
                size: gui::dpi(210, 20),
                resize_behavior: (gui::Horz::None, gui::Vert::None),
                ..Default::default()
            },
        );
        let summary_lbl = lbl(
            &page,
            "Idle — ready for ADB, Fastboot, or Offline Forensic Inspection.",
            230,
            12,
            340,
        );

        let filter_combo = gui::ComboBox::new(
            &page,
            gui::ComboBoxOpts {
                position: gui::dpi(580, 9),
                width: gui::dpi_x(135),
                items: &["All Records", "Devices/Pkgs/Props", "Transfers/Forensics", "Errors"],
                selected_item: Some(0),
                ..Default::default()
            },
        );
        let btn_copy_log = btn(&page, "Copy Log", 720, 8, 74, 24, (gui::Horz::None, gui::Vert::None));
        let btn_export_html = btn(&page, "HTML...", 798, 8, 64, 24, (gui::Horz::None, gui::Vert::None));
        let btn_export_all = btn(&page, "All...", 866, 8, 54, 24, (gui::Horz::None, gui::Vert::None));

        let actions_list = gui::ListView::new(
            &page,
            gui::ListViewOpts {
                position: gui::dpi(10, 40),
                size: gui::dpi(910, 210),
                columns: &[
                    ("Class", gui::dpi_x(90)),
                    ("Size", gui::dpi_x(90)),
                    ("Key / Path", gui::dpi_x(300)),
                    ("Detail", gui::dpi_x(410)),
                ],
                resize_behavior: (gui::Horz::None, gui::Vert::None),
                ..Default::default()
            },
        );

        let raw_log_edit = gui::Edit::new(
            &page,
            gui::EditOpts {
                position: gui::dpi(10, 260),
                width: gui::dpi_x(910),
                height: gui::dpi_y(210),
                control_style: co::ES::MULTILINE | co::ES::READONLY | co::ES::AUTOVSCROLL | co::ES::AUTOHSCROLL,
                window_style: co::WS::CHILD | co::WS::TABSTOP | co::WS::VISIBLE | co::WS::VSCROLL | co::WS::HSCROLL,
                resize_behavior: (gui::Horz::None, gui::Vert::None),
                ..Default::default()
            },
        );

        {
            let summary_lbl = summary_lbl.clone();
            let filter_combo = filter_combo.clone();
            let btn_copy_log = btn_copy_log.clone();
            let btn_export_html = btn_export_html.clone();
            let btn_export_all = btn_export_all.clone();
            let actions_list = actions_list.clone();
            let raw_log_edit = raw_log_edit.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let gap = gui::dpi_x(8);
                let sp = gui::dpi_x(4);
                let w_all = gui::dpi_x(54);
                let x_all = (w - pad - w_all).max(gui::dpi_x(720));
                let w_html = gui::dpi_x(64);
                let x_html = x_all - sp - w_html;
                let w_copy = gui::dpi_x(74);
                let x_copy = x_html - sp - w_copy;
                let w_flt = gui::dpi_x(135);
                let x_flt = x_copy - gui::dpi_x(6) - w_flt;

                move_ctrl(&btn_export_all, x_all, gui::dpi_y(8), w_all, gui::dpi_y(24));
                move_ctrl(&btn_export_html, x_html, gui::dpi_y(8), w_html, gui::dpi_y(24));
                move_ctrl(&btn_copy_log, x_copy, gui::dpi_y(8), w_copy, gui::dpi_y(24));
                repos_ctrl(&filter_combo, x_flt, gui::dpi_y(9));
                move_ctrl(
                    &summary_lbl,
                    gui::dpi_x(230),
                    gui::dpi_y(12),
                    (x_flt - gap - gui::dpi_x(230)).max(gui::dpi_x(100)),
                    gui::dpi_y(18),
                );

                let top_y = gui::dpi_y(40);
                let avail_h = (h - top_y - gui::dpi_y(18)).max(gui::dpi_y(160));
                let act_h = (avail_h / 2).max(gui::dpi_y(120));
                let full_w = (w - 2 * pad).max(gui::dpi_x(200));
                move_ctrl(&actions_list, pad, top_y, full_w, act_h);
                let raw_y = top_y + act_h + gui::dpi_y(8);
                move_ctrl(
                    &raw_log_edit,
                    pad,
                    raw_y,
                    full_w,
                    (h - raw_y - gui::dpi_y(10)).max(gui::dpi_y(80)),
                );
                Ok(())
            });
        }

        Self {
            page,
            progress,
            summary_lbl,
            filter_combo,
            btn_copy_log,
            btn_export_html,
            btn_export_all,
            actions_list,
            raw_log_edit,
        }
    }
}

#[derive(Clone)]
struct BatchHistoryPage {
    page: gui::TabPage,
    btn_add: gui::Button,
    btn_dry_queue: gui::Button,
    btn_run_queue: gui::Button,
    btn_remove: gui::Button,
    btn_clear_queue: gui::Button,
    chk_stop_err: gui::CheckBox,
    batch_list: gui::ListView,
    btn_reload_hist: gui::Button,
    btn_clear_hist: gui::Button,
    hist_list: gui::ListView,
    code_edit: gui::Edit,
    btn_decode: gui::Button,
    decode_lbl: gui::Label,
}

impl BatchHistoryPage {
    fn new(parent: &(impl GuiParent + 'static)) -> Self {
        let page = tab_page(parent);

        let btn_add = btn(&page, "Add Current", 10, 8, 95, 24, (gui::Horz::None, gui::Vert::None));
        let btn_dry_queue = btn(
            &page,
            "Dry-Run Queue",
            110,
            8,
            105,
            24,
            (gui::Horz::None, gui::Vert::None),
        );
        let btn_run_queue = btn(&page, "Run Queue", 220, 8, 90, 24, (gui::Horz::None, gui::Vert::None));
        let btn_remove = btn(&page, "Remove Sel", 315, 8, 90, 24, (gui::Horz::None, gui::Vert::None));
        let btn_clear_queue = btn(&page, "Clear Queue", 410, 8, 90, 24, (gui::Horz::None, gui::Vert::None));
        let chk_stop_err = chk(&page, "Stop on Error", 515, 11);

        let batch_list = gui::ListView::new(
            &page,
            gui::ListViewOpts {
                position: gui::dpi(10, 38),
                size: gui::dpi(940, 170),
                columns: &[
                    ("#", gui::dpi_x(40)),
                    ("Job Name", gui::dpi_x(170)),
                    ("Operation", gui::dpi_x(170)),
                    ("Source / Target", gui::dpi_x(300)),
                    ("Status", gui::dpi_x(105)),
                    ("Notes", gui::dpi_x(145)),
                ],
                resize_behavior: (gui::Horz::None, gui::Vert::None),
                ..Default::default()
            },
        );

        lbl(&page, "Run History:", 10, 218, 85);
        let btn_reload_hist = btn(
            &page,
            "Reload Command",
            100,
            214,
            115,
            24,
            (gui::Horz::None, gui::Vert::None),
        );
        let btn_clear_hist = btn(
            &page,
            "Clear History",
            220,
            214,
            95,
            24,
            (gui::Horz::None, gui::Vert::None),
        );

        lbl(&page, "Decode Status:", 330, 218, 92);
        let code_edit = edit(&page, 425, 215, 195, 22, (gui::Horz::None, gui::Vert::None));
        let btn_decode = btn(&page, "Decode", 625, 214, 65, 24, (gui::Horz::None, gui::Vert::None));
        let decode_lbl = lbl(
            &page,
            "DEVICE_UNAUTHORIZED -> Accept USB debugging RSA prompt",
            698,
            218,
            250,
        );

        let hist_list = gui::ListView::new(
            &page,
            gui::ListViewOpts {
                position: gui::dpi(10, 244),
                size: gui::dpi(940, 240),
                columns: &[
                    ("Timestamp", gui::dpi_x(155)),
                    ("Job", gui::dpi_x(150)),
                    ("Mode", gui::dpi_x(70)),
                    ("Status", gui::dpi_x(125)),
                    ("Recs / Errs", gui::dpi_x(85)),
                    ("Paths", gui::dpi_x(345)),
                ],
                resize_behavior: (gui::Horz::None, gui::Vert::None),
                ..Default::default()
            },
        );

        {
            let batch_list = batch_list.clone();
            let decode_lbl = decode_lbl.clone();
            let hist_list = hist_list.clone();
            page.on().wm_size(move |p| {
                if p.request == co::SIZE_R::MINIMIZED || p.client_area.cx <= 0 || p.client_area.cy <= 0 {
                    return Ok(());
                }
                let w = p.client_area.cx;
                let h = p.client_area.cy;
                let pad = gui::dpi_x(10);
                let full_w = (w - 2 * pad).max(gui::dpi_x(200));
                move_ctrl(&batch_list, pad, gui::dpi_y(38), full_w, gui::dpi_y(170));
                move_ctrl(
                    &decode_lbl,
                    gui::dpi_x(698),
                    gui::dpi_y(218),
                    (w - gui::dpi_x(698) - pad).max(gui::dpi_x(120)),
                    gui::dpi_y(18),
                );
                move_ctrl(
                    &hist_list,
                    pad,
                    gui::dpi_y(244),
                    full_w,
                    (h - gui::dpi_y(244) - gui::dpi_y(10)).max(gui::dpi_y(80)),
                );
                Ok(())
            });
        }

        Self {
            page,
            btn_add,
            btn_dry_queue,
            btn_run_queue,
            btn_remove,
            btn_clear_queue,
            chk_stop_err,
            batch_list,
            btn_reload_hist,
            btn_clear_hist,
            hist_list,
            code_edit,
            btn_decode,
            decode_lbl,
        }
    }
}

#[derive(Clone)]
struct Win32App {
    wnd: gui::WindowMain,
    op_combo: gui::ComboBox,
    serial_edit: gui::Edit,
    src_edit: gui::Edit,
    btn_src_file: gui::Button,
    btn_src_dir: gui::Button,
    tgt_edit: gui::Edit,
    btn_tgt_dir: gui::Button,

    preset_combo: gui::ComboBox,
    btn_apply_preset: gui::Button,
    profile_combo: gui::ComboBox,
    btn_load_prof: gui::Button,
    btn_save_prof: gui::Button,
    btn_del_prof: gui::Button,
    btn_dry_run: gui::Button,
    btn_run_job: gui::Button,
    btn_queue_add: gui::Button,
    btn_stop_job: gui::Button,

    tab: gui::Tab,
    tab_pages: Vec<gui::TabPage>,
    designer: DesignerPage,
    adb_pg: AdbPackagesPage,
    transfer_pg: TransferLogcatPage,
    fastboot_pg: FastbootPage,
    forensics_pg: ForensicsPage,
    console_pg: ConsolePage,
    batch_pg: BatchHistoryPage,

    cmd_edit: gui::Edit,
    btn_copy_cmd: gui::Button,
    btn_exp_recipe: gui::Button,
    btn_exp_bat: gui::Button,
    btn_exp_ps1: gui::Button,
    btn_exp_sh: gui::Button,
    status_bar: gui::StatusBar,

    state: Arc<Mutex<Win32State>>,
    suppress_sync: Arc<AtomicBool>,
}

fn build_main_menu() -> w::SysResult<w::HMENU> {
    let menu = w::HMENU::CreateMenu()?;
    let file_m = w::HMENU::CreatePopupMenu()?;
    file_m.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_IMPORT_RECIPE,
            text: "Import .a2r Recipe...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_RECIPE,
            text: "Export .a2r Recipe...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_BAT,
            text: "Export .bat Script...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_PS1,
            text: "Export .ps1 PowerShell Script...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_EXPORT_SH,
            text: "Export .sh Shell Script...",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_REPORT_HTML,
            text: "Export Last Run HTML Report...",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_REPORT_ALL,
            text: "Export Last Run Bundle (All)...",
        },
        w::MenuItem::Separator,
        w::MenuItem::Entry {
            cmd_id: IDM_EXIT,
            text: "Exit",
        },
    ])?;

    let job_m = w::HMENU::CreatePopupMenu()?;
    job_m.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_RESET_JOB,
            text: "Reset Default Job",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_COPY_CMD,
            text: "Copy Command Line",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_SAVE_PROFILE,
            text: "Save Profile",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_QUEUE_ADD,
            text: "Add Current Job to Batch Queue",
        },
    ])?;

    let exec_m = w::HMENU::CreatePopupMenu()?;
    exec_m.append_item(&[
        w::MenuItem::Entry {
            cmd_id: IDM_DRY_RUN,
            text: "Dry-Run Preview",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_RUN_JOB,
            text: "Execute Job",
        },
        w::MenuItem::Entry {
            cmd_id: IDM_STOP_JOB,
            text: "Stop Active Job",
        },
    ])?;

    let help_m = w::HMENU::CreatePopupMenu()?;
    help_m.append_item(&[w::MenuItem::Entry {
        cmd_id: IDM_ABOUT,
        text: "About Android2Rust Win32...",
    }])?;

    menu.append_item(&[
        w::MenuItem::Submenu {
            submenu: &file_m,
            text: "&File",
        },
        w::MenuItem::Submenu {
            submenu: &job_m,
            text: "&Job",
        },
        w::MenuItem::Submenu {
            submenu: &exec_m,
            text: "&Execution",
        },
        w::MenuItem::Submenu {
            submenu: &help_m,
            text: "&Help",
        },
    ])?;
    Ok(menu)
}

pub fn run(launch: LaunchArgs) -> anyhow::Result<()> {
    let hmenu = build_main_menu().map_err(|e| anyhow::anyhow!("Menu creation failed: {e}"))?;
    let state = Arc::new(Mutex::new(Win32State::new(&launch)));

    let wnd = gui::WindowMain::new(gui::WindowMainOpts {
        title: "Android2Rust Management & Forensics Console (Native Win32)",
        size: gui::dpi(1040, 670),
        style: co::WS::CAPTION
            | co::WS::SYSMENU
            | co::WS::CLIPCHILDREN
            | co::WS::BORDER
            | co::WS::VISIBLE
            | co::WS::SIZEBOX
            | co::WS::MINIMIZEBOX
            | co::WS::MAXIMIZEBOX,
        class_icon: gui::Icon::Id(101),
        class_bg_brush: gui::Brush::Color(co::COLOR::BTNFACE),
        menu: hmenu,
        ..Default::default()
    });

    // Row 1: Operation, Serial, Source/Artifact, Target/Partition
    lbl(&wnd, "Op:", 10, 12, 24);
    let op_combo = gui::ComboBox::new(
        &wnd,
        gui::ComboBoxOpts {
            position: gui::dpi(36, 9),
            width: gui::dpi_x(190),
            ..Default::default()
        },
    );
    lbl(&wnd, "Serial:", 232, 12, 42);
    let serial_edit = edit(&wnd, 276, 9, 100, 22, (gui::Horz::None, gui::Vert::None));
    lbl(&wnd, "Src/File:", 382, 12, 54);
    let src_edit = edit(&wnd, 438, 9, 210, 22, (gui::Horz::None, gui::Vert::None));
    let btn_src_file = btn(&wnd, "File", 652, 8, 40, 24, (gui::Horz::None, gui::Vert::None));
    let btn_src_dir = btn(&wnd, "Dir", 696, 8, 36, 24, (gui::Horz::None, gui::Vert::None));
    lbl(&wnd, "Target:", 738, 12, 46);
    let tgt_edit = edit(&wnd, 786, 9, 200, 22, (gui::Horz::Resize, gui::Vert::None));
    let btn_tgt_dir = btn(&wnd, "...", 990, 8, 36, 24, (gui::Horz::Repos, gui::Vert::None));

    // Row 2: Presets, Profiles, Execution
    lbl(&wnd, "Preset:", 10, 40, 48);
    let preset_combo = gui::ComboBox::new(
        &wnd,
        gui::ComboBoxOpts {
            position: gui::dpi(60, 37),
            width: gui::dpi_x(195),
            ..Default::default()
        },
    );
    let btn_apply_preset = btn(&wnd, "Apply", 259, 36, 52, 24, (gui::Horz::None, gui::Vert::None));
    lbl(&wnd, "Profile:", 318, 40, 46);
    let profile_combo = gui::ComboBox::new(
        &wnd,
        gui::ComboBoxOpts {
            position: gui::dpi(366, 37),
            width: gui::dpi_x(150),
            ..Default::default()
        },
    );
    let btn_load_prof = btn(&wnd, "Load", 520, 36, 46, 24, (gui::Horz::None, gui::Vert::None));
    let btn_save_prof = btn(&wnd, "Save", 570, 36, 46, 24, (gui::Horz::None, gui::Vert::None));
    let btn_del_prof = btn(&wnd, "Del", 620, 36, 38, 24, (gui::Horz::None, gui::Vert::None));

    let btn_dry_run = btn(&wnd, "Dry-Run", 730, 36, 76, 24, (gui::Horz::Repos, gui::Vert::None));
    let btn_run_job = btn(&wnd, "Run Job", 810, 36, 76, 24, (gui::Horz::Repos, gui::Vert::None));
    let btn_queue_add = btn(&wnd, "Queue +", 890, 36, 68, 24, (gui::Horz::Repos, gui::Vert::None));
    let btn_stop_job = btn(&wnd, "Stop", 962, 36, 64, 24, (gui::Horz::Repos, gui::Vert::None));

    // Center Tab Control
    let designer = DesignerPage::new(&wnd);
    let adb_pg = AdbPackagesPage::new(&wnd);
    let transfer_pg = TransferLogcatPage::new(&wnd);
    let fastboot_pg = FastbootPage::new(&wnd);
    let forensics_pg = ForensicsPage::new(&wnd);
    let console_pg = ConsolePage::new(&wnd);
    let batch_pg = BatchHistoryPage::new(&wnd);

    let tab_pages = vec![
        designer.page.clone(),
        adb_pg.page.clone(),
        transfer_pg.page.clone(),
        fastboot_pg.page.clone(),
        forensics_pg.page.clone(),
        console_pg.page.clone(),
        batch_pg.page.clone(),
    ];

    let tab = gui::Tab::new(
        &wnd,
        gui::TabOpts {
            position: gui::dpi(10, 66),
            size: gui::dpi(1018, 540),
            resize_behavior: (gui::Horz::Resize, gui::Vert::Resize),
            pages: &[
                ("Designer && Diagnostics", designer.page.clone()),
                ("ADB && Packages", adb_pg.page.clone()),
                ("Transfer && Logcat", transfer_pg.page.clone()),
                ("Fastboot && Flash", fastboot_pg.page.clone()),
                ("Forensics && Artifacts", forensics_pg.page.clone()),
                ("Live Console && Records", console_pg.page.clone()),
                ("Batch && History", batch_pg.page.clone()),
            ],
            ..Default::default()
        },
    );

    // Bottom Command Bar
    let _ = gui::Label::new(
        &wnd,
        gui::LabelOpts {
            text: "CMD:",
            position: gui::dpi(10, 616),
            size: gui::dpi(38, 18),
            resize_behavior: (gui::Horz::None, gui::Vert::Repos),
            ..Default::default()
        },
    );
    let cmd_edit = gui::Edit::new(
        &wnd,
        gui::EditOpts {
            position: gui::dpi(50, 613),
            width: gui::dpi_x(715),
            height: gui::dpi_y(22),
            control_style: co::ES::AUTOHSCROLL | co::ES::READONLY,
            resize_behavior: (gui::Horz::Resize, gui::Vert::Repos),
            ..Default::default()
        },
    );
    let btn_copy_cmd = btn(&wnd, "Copy", 772, 612, 54, 24, (gui::Horz::Repos, gui::Vert::Repos));
    let btn_exp_recipe = btn(&wnd, ".a2r", 830, 612, 46, 24, (gui::Horz::Repos, gui::Vert::Repos));
    let btn_exp_bat = btn(&wnd, ".bat", 880, 612, 46, 24, (gui::Horz::Repos, gui::Vert::Repos));
    let btn_exp_ps1 = btn(&wnd, ".ps1", 930, 612, 46, 24, (gui::Horz::Repos, gui::Vert::Repos));
    let btn_exp_sh = btn(&wnd, ".sh", 980, 612, 46, 24, (gui::Horz::Repos, gui::Vert::Repos));

    // Bottom StatusBar
    let status_bar = gui::StatusBar::new(
        &wnd,
        &[
            gui::SbPart::Proportional(2),
            gui::SbPart::Fixed(gui::dpi_x(175)),
            gui::SbPart::Fixed(gui::dpi_x(185)),
            gui::SbPart::Fixed(gui::dpi_x(215)),
        ],
    );

    let app = Win32App {
        wnd,
        op_combo,
        serial_edit,
        src_edit,
        btn_src_file,
        btn_src_dir,
        tgt_edit,
        btn_tgt_dir,
        preset_combo,
        btn_apply_preset,
        profile_combo,
        btn_load_prof,
        btn_save_prof,
        btn_del_prof,
        btn_dry_run,
        btn_run_job,
        btn_queue_add,
        btn_stop_job,
        tab,
        tab_pages,
        designer,
        adb_pg,
        transfer_pg,
        fastboot_pg,
        forensics_pg,
        console_pg,
        batch_pg,
        cmd_edit,
        btn_copy_cmd,
        btn_exp_recipe,
        btn_exp_bat,
        btn_exp_ps1,
        btn_exp_sh,
        status_bar,
        state,
        suppress_sync: Arc::new(AtomicBool::new(false)),
    };

    app.register_events();
    app.wnd
        .run_main(None)
        .map_err(|e| anyhow::anyhow!("Win32 message loop error: {e}"))?;
    Ok(())
}

impl Win32App {
    fn select_tab_index(&self, idx: u32) {
        unsafe {
            self.tab.hwnd().SendMessage(msg::TcmSetCurSel { index: idx });
        }
        self.layout_active_tab_page(idx);
    }

    fn layout_active_tab_page(&self, active_idx: u32) {
        for (i, pg) in self.tab_pages.iter().enumerate() {
            if i as u32 != active_idx {
                let _ = pg.hwnd().ShowWindow(co::SW::HIDE);
            }
        }
        if let Some(pg) = self.tab_pages.get(active_idx as usize)
            && let Ok(tab_rc) = self.tab.hwnd().GetWindowRect()
            && let Ok(mut rc) = self.wnd.hwnd().ScreenToClientRc(tab_rc)
        {
            unsafe {
                self.tab.hwnd().SendMessage(msg::TcmAdjustRect {
                    display_rect: false,
                    rect: &mut rc,
                });
            }
            let _ = pg.hwnd().SetWindowPos(
                w::HwndPlace::None,
                w::POINT::with(rc.left, rc.top),
                w::SIZE::with((rc.right - rc.left).max(10), (rc.bottom - rc.top).max(10)),
                co::SWP::NOZORDER | co::SWP::SHOWWINDOW,
            );
        }
    }

    fn sync_job_to_controls(&self) {
        self.suppress_sync.store(true, Ordering::SeqCst);
        let st = self.state.lock().unwrap();
        let j = &st.job;

        if let Some(pos) = AndroidOperation::ALL.iter().position(|&o| o == j.operation) {
            self.op_combo.items().select(Some(pos as u32));
        }
        let _ = self.serial_edit.set_text(&j.serial);
        let _ = self.src_edit.set_text(&j.source_path);
        let _ = self.tgt_edit.set_text(&j.target_path);

        let _ = self.designer.job_name.set_text(&j.name);
        let _ = self.designer.job_desc.set_text(&j.description);
        let _ = self.designer.import_cmd.set_text(&st.cached_command);

        self.adb_pg.third_party.set_check(j.package_opts.third_party_only);
        self.adb_pg.system_only.set_check(j.package_opts.system_only);
        self.adb_pg.show_apk_path.set_check(j.package_opts.show_apk_path);
        self.adb_pg.show_installer.set_check(j.package_opts.show_installer);
        self.adb_pg.show_uid.set_check(j.package_opts.show_uid);
        self.adb_pg.reinstall.set_check(j.package_opts.reinstall);
        self.adb_pg.allow_downgrade.set_check(j.package_opts.allow_downgrade);
        self.adb_pg.grant_perms.set_check(j.package_opts.grant_permissions);
        self.adb_pg.keep_data.set_check(j.package_opts.keep_data);
        let _ = self
            .adb_pg
            .user_id
            .set_text(&j.package_opts.user_id.map(|v| v.to_string()).unwrap_or_default());
        let reboot_idx = match j.reboot_target {
            RebootTarget::System => 0,
            RebootTarget::Bootloader => 1,
            RebootTarget::Recovery => 2,
            RebootTarget::Fastbootd => 3,
            RebootTarget::Sideload => 4,
        };
        self.adb_pg.reboot_combo.items().select(Some(reboot_idx));

        self.transfer_pg
            .preserve_ts
            .set_check(j.transfer_opts.preserve_timestamps);
        self.transfer_pg.sync_newer.set_check(j.transfer_opts.sync_only_newer);
        let _ = self
            .transfer_pg
            .compression
            .set_text(j.transfer_opts.compression.as_deref().unwrap_or(""));
        self.transfer_pg.bak_apk.set_check(j.backup_opts.include_apk);
        self.transfer_pg.bak_obb.set_check(j.backup_opts.include_obb);
        self.transfer_pg.bak_shared.set_check(j.backup_opts.include_shared);
        self.transfer_pg.bak_all.set_check(j.backup_opts.all_apps);
        self.transfer_pg.bak_system.set_check(j.backup_opts.include_system);
        let _ = self
            .transfer_pg
            .bak_packages
            .set_text(&join_tokens(&j.backup_opts.packages));
        let _ = self
            .transfer_pg
            .log_buffers
            .set_text(&join_tokens(&j.logcat_opts.buffers));
        let _ = self.transfer_pg.log_format.set_text(&j.logcat_opts.format);
        let _ = self
            .transfer_pg
            .log_max_lines
            .set_text(&j.logcat_opts.max_lines.map(|v| v.to_string()).unwrap_or_default());
        self.transfer_pg.log_dump.set_check(j.logcat_opts.dump_and_exit);
        self.transfer_pg.log_clear.set_check(j.logcat_opts.clear_first);
        let _ = self
            .transfer_pg
            .log_filters
            .set_text(&join_tokens(&j.logcat_opts.filter_specs));

        let _ = self.fastboot_pg.partition.set_text(&j.fastboot_opts.partition);
        let _ = self
            .fastboot_pg
            .slot
            .set_text(j.fastboot_opts.slot.as_deref().unwrap_or(""));
        self.fastboot_pg.skip_reboot.set_check(j.fastboot_opts.skip_reboot);
        self.fastboot_pg.wipe_userdata.set_check(j.fastboot_opts.wipe_userdata);
        self.fastboot_pg
            .disable_verity
            .set_check(j.fastboot_opts.disable_verity);
        self.fastboot_pg
            .disable_verification
            .set_check(j.fastboot_opts.disable_verification);

        self.forensics_pg.sha256.set_check(j.forensic_opts.compute_sha256);
        self.forensics_pg
            .manifest_perms
            .set_check(j.forensic_opts.extract_manifest_permissions);
        self.forensics_pg
            .sqlite_tables
            .set_check(j.forensic_opts.inspect_sqlite_tables);
        self.forensics_pg
            .ab_tar
            .set_check(j.forensic_opts.inspect_ab_tar_entries);
        let _ = self
            .forensics_pg
            .max_entries
            .set_text(&j.forensic_opts.max_entries.to_string());
        let _ = self.forensics_pg.extra_args.set_text(&join_tokens(&j.extra_args));

        drop(st);
        self.suppress_sync.store(false, Ordering::SeqCst);
        self.refresh_derived_views();
    }

    fn sync_controls_to_job(&self) {
        if self.suppress_sync.load(Ordering::SeqCst) {
            return;
        }
        {
            let mut st = self.state.lock().unwrap();
            let j = &mut st.job;

            if let Some(idx) = self.op_combo.items().selected_index()
                && let Some(&op) = AndroidOperation::ALL.get(idx as usize)
            {
                j.operation = op;
                j.tool = op.default_tool();
            }
            j.serial = self.serial_edit.text().unwrap_or_default().trim().to_string();
            j.transport = if j.serial.is_empty() {
                TransportMode::Auto
            } else {
                TransportMode::Serial(j.serial.clone())
            };
            j.source_path = self.src_edit.text().unwrap_or_default();
            j.target_path = self.tgt_edit.text().unwrap_or_default();

            j.name = self.designer.job_name.text().unwrap_or_default();
            j.description = self.designer.job_desc.text().unwrap_or_default();

            j.package_opts.third_party_only = self.adb_pg.third_party.is_checked();
            j.package_opts.system_only = self.adb_pg.system_only.is_checked();
            j.package_opts.show_apk_path = self.adb_pg.show_apk_path.is_checked();
            j.package_opts.show_installer = self.adb_pg.show_installer.is_checked();
            j.package_opts.show_uid = self.adb_pg.show_uid.is_checked();
            j.package_opts.reinstall = self.adb_pg.reinstall.is_checked();
            j.package_opts.allow_downgrade = self.adb_pg.allow_downgrade.is_checked();
            j.package_opts.grant_permissions = self.adb_pg.grant_perms.is_checked();
            j.package_opts.keep_data = self.adb_pg.keep_data.is_checked();
            j.package_opts.user_id = self.adb_pg.user_id.text().ok().and_then(|s| s.trim().parse().ok());
            j.reboot_target = match self.adb_pg.reboot_combo.items().selected_index() {
                Some(1) => RebootTarget::Bootloader,
                Some(2) => RebootTarget::Recovery,
                Some(3) => RebootTarget::Fastbootd,
                Some(4) => RebootTarget::Sideload,
                _ => RebootTarget::System,
            };

            j.transfer_opts.preserve_timestamps = self.transfer_pg.preserve_ts.is_checked();
            j.transfer_opts.sync_only_newer = self.transfer_pg.sync_newer.is_checked();
            let comp = self.transfer_pg.compression.text().unwrap_or_default();
            j.transfer_opts.compression = if comp.trim().is_empty() {
                None
            } else {
                Some(comp.trim().to_string())
            };
            j.backup_opts.include_apk = self.transfer_pg.bak_apk.is_checked();
            j.backup_opts.include_obb = self.transfer_pg.bak_obb.is_checked();
            j.backup_opts.include_shared = self.transfer_pg.bak_shared.is_checked();
            j.backup_opts.all_apps = self.transfer_pg.bak_all.is_checked();
            j.backup_opts.include_system = self.transfer_pg.bak_system.is_checked();
            j.backup_opts.packages = split_tokens(&self.transfer_pg.bak_packages.text().unwrap_or_default());

            j.logcat_opts.buffers = split_tokens(&self.transfer_pg.log_buffers.text().unwrap_or_default());
            j.logcat_opts.format = self.transfer_pg.log_format.text().unwrap_or_default();
            j.logcat_opts.max_lines = self
                .transfer_pg
                .log_max_lines
                .text()
                .ok()
                .and_then(|s| s.trim().parse().ok());
            j.logcat_opts.dump_and_exit = self.transfer_pg.log_dump.is_checked();
            j.logcat_opts.clear_first = self.transfer_pg.log_clear.is_checked();
            j.logcat_opts.filter_specs = split_tokens(&self.transfer_pg.log_filters.text().unwrap_or_default());

            j.fastboot_opts.partition = self.fastboot_pg.partition.text().unwrap_or_default();
            let slot_txt = self.fastboot_pg.slot.text().unwrap_or_default();
            j.fastboot_opts.slot = if slot_txt.trim().is_empty() {
                None
            } else {
                Some(slot_txt.trim().to_string())
            };
            j.fastboot_opts.skip_reboot = self.fastboot_pg.skip_reboot.is_checked();
            j.fastboot_opts.wipe_userdata = self.fastboot_pg.wipe_userdata.is_checked();
            j.fastboot_opts.disable_verity = self.fastboot_pg.disable_verity.is_checked();
            j.fastboot_opts.disable_verification = self.fastboot_pg.disable_verification.is_checked();

            j.forensic_opts.compute_sha256 = self.forensics_pg.sha256.is_checked();
            j.forensic_opts.extract_manifest_permissions = self.forensics_pg.manifest_perms.is_checked();
            j.forensic_opts.inspect_sqlite_tables = self.forensics_pg.sqlite_tables.is_checked();
            j.forensic_opts.inspect_ab_tar_entries = self.forensics_pg.ab_tar.is_checked();
            if let Some(m) = self
                .forensics_pg
                .max_entries
                .text()
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
            {
                j.forensic_opts.max_entries = m.max(10);
            }
            j.extra_args = split_tokens(&self.forensics_pg.extra_args.text().unwrap_or_default());

            st.refresh_derived();
        }
        self.refresh_derived_views();
    }

    fn refresh_derived_views(&self) {
        let st = self.state.lock().unwrap();
        let _ = self.cmd_edit.set_text(&st.cached_command);
        self.update_schtasks_preview(&st.cached_command);

        self.designer.diag_list.set_redraw(false);
        let _ = self.designer.diag_list.items().delete_all();
        if st.findings.is_empty() {
            let _ = self.designer.diag_list.items().add(
                &["OK", "VALID", "No configuration conflicts or hazards detected.", "-"],
                None,
                (),
            );
        } else {
            for f in &st.findings {
                let sev = match f.severity {
                    ValidationSeverity::Error => "ERROR",
                    ValidationSeverity::Warning => "WARN",
                    ValidationSeverity::Info => "INFO",
                };
                let _ = self.designer.diag_list.items().add(
                    &[sev, &f.code, &f.message, f.suggestion.as_deref().unwrap_or("-")],
                    None,
                    (),
                );
            }
        }
        self.designer.diag_list.set_redraw(true);
        self.refresh_status_bar(&st);
    }

    fn update_schtasks_preview(&self, cmd_line: &str) {
        let task_name = self.designer.sch_name.text().unwrap_or_default();
        let cadence = match self.designer.sch_cadence.items().selected_index() {
            Some(1) => ScheduleCadence::Weekly,
            Some(2) => ScheduleCadence::Hourly,
            Some(3) => ScheduleCadence::OnStart,
            Some(4) => ScheduleCadence::OnLogon,
            _ => ScheduleCadence::Daily,
        };
        let spec = ScheduleSpec {
            cadence,
            start_time: self.designer.sch_time.text().unwrap_or_else(|_| "02:00".to_string()),
            days: Some("MON,WED,FRI".to_string()),
            run_highest: self.designer.sch_highest.is_checked(),
        };
        let cmd = build_schtasks_command(&task_name, cmd_line, &spec);
        let _ = self.designer.sch_preview.set_text(&cmd);
    }

    fn refresh_status_bar(&self, st: &Win32State) {
        let _ = self.status_bar.parts().get(0).set_text(&st.status_message);
        let diag = if st.error_count() > 0 {
            format!("{} Err / {} Warn", st.error_count(), st.warning_count())
        } else if st.warning_count() > 0 {
            format!("{} Warning(s)", st.warning_count())
        } else {
            "Config Valid".to_string()
        };
        let _ = self.status_bar.parts().get(1).set_text(&diag);

        let run_seg = if st.is_running {
            format!("RUNNING ({:.0}%)", st.live_progress_pct)
        } else if let Some(res) = &st.last_result {
            format!("Last: {}", res.status_info.short_label)
        } else {
            "Idle".to_string()
        };
        let _ = self.status_bar.parts().get(2).set_text(&run_seg);

        let env_seg = if st.env.adb_available {
            "Win32 | ADB + Forensics Ready"
        } else {
            "Win32 | Offline Forensics Ready"
        };
        let _ = self.status_bar.parts().get(3).set_text(env_seg);
    }

    fn refresh_profile_combo(&self) {
        let st = self.state.lock().unwrap();
        self.profile_combo.items().delete_all();
        let names: Vec<String> = st.profiles.iter().map(|p| p.name.clone()).collect();
        if !names.is_empty() {
            let _ = self.profile_combo.items().add(&names);
            self.profile_combo.items().select(Some(0));
        }
    }

    fn refresh_batch_and_history_lists(&self) {
        let st = self.state.lock().unwrap();

        self.batch_pg.batch_list.set_redraw(false);
        let _ = self.batch_pg.batch_list.items().delete_all();
        for (i, item) in st.batch_items.iter().enumerate() {
            let idx_str = (i + 1).to_string();
            let status_str = item.status.label();
            let paths = format!("{} -> {}", item.job.source_path, item.job.target_path);
            let _ = self.batch_pg.batch_list.items().add(
                &[
                    &idx_str,
                    &item.job.name,
                    item.job.operation.label(),
                    &paths,
                    &status_str,
                    &item.note,
                ],
                None,
                (),
            );
        }
        self.batch_pg.batch_list.set_redraw(true);

        self.batch_pg.hist_list.set_redraw(false);
        let _ = self.batch_pg.hist_list.items().delete_all();
        for h in &st.run_history {
            let mode = if h.dry_run { "Dry-Run" } else { "Live" };
            let recs = format!("{}/{}", h.records_count, h.error_count);
            let paths = format!("{} -> {}", h.source, h.destination);
            let _ = self.batch_pg.hist_list.items().add(
                &[&h.timestamp, &h.job_name, mode, &h.exit_label, &recs, &paths],
                None,
                (),
            );
        }
        self.batch_pg.hist_list.set_redraw(true);
    }

    fn refresh_action_list(&self) {
        let st = self.state.lock().unwrap();
        let filter = ActionFilter::from_index(self.console_pg.filter_combo.items().selected_index());
        self.console_pg.actions_list.set_redraw(false);
        let _ = self.console_pg.actions_list.items().delete_all();
        for rec in &st.live_file_actions {
            if !filter.matches(rec) {
                continue;
            }
            let sz = rec.size_bytes.map(format_bytes).unwrap_or_else(|| "-".to_string());
            let _ =
                self.console_pg
                    .actions_list
                    .items()
                    .add(&[rec.kind.label(), &sz, &rec.path, &rec.detail], None, ());
        }
        self.console_pg.actions_list.set_redraw(true);
    }

    fn trigger_dry_run(&self) {
        let dry = {
            let st = self.state.lock().unwrap();
            if st.is_running {
                return;
            }
            st.job.with_dry_run()
        };
        let _ = self.start_execution(dry);
    }

    fn trigger_execute(&self) {
        let job = {
            let mut st = self.state.lock().unwrap();
            if st.is_running {
                return;
            }
            st.refresh_derived();
            if st.error_count() > 0 {
                st.status_message = "Cannot run: fix validation errors first.".to_string();
                self.refresh_status_bar(&st);
                let _ = self.wnd.hwnd().MessageBox(
                    "Please resolve the red configuration errors shown in Designer & Diagnostics before running.",
                    "Validation Error",
                    co::MB::ICONERROR,
                );
                return;
            }
            let mut j = st.job.clone();
            j.dry_run = false;
            j
        };

        if job.is_destructive() {
            let reasons = job.destructive_reasons().join(", ");
            let msg_txt = format!(
                "Destructive Android operation(s): {reasons}\n\nSerial: {}\nSource/Image: {}\nTarget/Partition: {}\n\nClick YES to Execute destructively.\nClick NO to run a safe Dry-Run preview instead.\nClick CANCEL to abort.",
                job.serial, job.source_path, job.target_path
            );
            match self.wnd.hwnd().MessageBox(
                &msg_txt,
                "Confirm Destructive Android Operation",
                co::MB::YESNOCANCEL | co::MB::ICONWARNING,
            ) {
                Ok(co::DLGID::YES) => {
                    let _ = self.start_execution(job);
                }
                Ok(co::DLGID::NO) => {
                    let _ = self.start_execution(job.with_dry_run());
                }
                _ => {}
            }
            return;
        }
        let _ = self.start_execution(job);
    }

    fn start_batch_from(&self, mut idx: usize) {
        loop {
            let next_job = {
                let mut st = self.state.lock().unwrap();
                if !st.batch_running || idx >= st.batch_items.len() {
                    st.batch_running = false;
                    st.active_batch_idx = None;
                    self.refresh_status_bar(&st);
                    None
                } else {
                    st.active_batch_idx = Some(idx);
                    st.batch_items[idx].status = BatchStatus::Running;
                    st.batch_items[idx].note = "Running...".to_string();
                    let mut j = st.batch_items[idx].job.clone();
                    if st.batch_dry_run {
                        j = j.with_dry_run();
                    } else {
                        j.dry_run = false;
                    }
                    Some(j)
                }
            };
            self.refresh_batch_and_history_lists();
            let Some(job) = next_job else {
                return;
            };
            if self.start_execution(job) {
                return;
            }
            let should_continue = {
                let mut st = self.state.lock().unwrap();
                if idx < st.batch_items.len() {
                    st.batch_items[idx].status = BatchStatus::Failed(1);
                    st.batch_items[idx].note = "Validation Error".to_string();
                }
                if st.batch_stop_on_error {
                    st.batch_running = false;
                    st.active_batch_idx = None;
                    st.status_message = format!("Batch stopped at item #{} (validation error).", idx + 1);
                    self.refresh_status_bar(&st);
                    false
                } else {
                    true
                }
            };
            self.refresh_batch_and_history_lists();
            if !should_continue {
                return;
            }
            idx += 1;
        }
    }

    fn start_execution(&self, job: AndroidJob) -> bool {
        let errs: Vec<_> = android2rust_core::validate_job(&job)
            .into_iter()
            .filter(|f| f.severity == ValidationSeverity::Error)
            .collect();
        if !errs.is_empty() {
            let _ = self
                .wnd
                .hwnd()
                .MessageBox(&errs[0].message, "Validation Error", co::MB::ICONERROR);
            return false;
        }

        self.select_tab_index(TAB_CONSOLE_IDX);
        self.console_pg.progress.set_range(0, 100);
        self.console_pg.progress.set_position(0);
        self.console_pg.actions_list.set_redraw(false);
        let _ = self.console_pg.actions_list.items().delete_all();
        self.console_pg.actions_list.set_redraw(true);
        let _ = self.console_pg.raw_log_edit.set_text("");

        let (rx, cancel) = spawn_job_runner(job.clone(), None);
        {
            let mut st = self.state.lock().unwrap();
            st.is_running = true;
            st.cancel_token = Some(cancel);
            st.live_progress_pct = 0.0;
            st.live_summary = Default::default();
            st.live_log_lines.clear();
            st.live_file_actions.clear();
            st.last_result = None;
            st.status_message = if job.dry_run {
                format!("Running Dry-Run: {}", job.name)
            } else {
                format!("Executing {}: {}", job.tool.label(), job.name)
            };
            self.refresh_status_bar(&st);
        }
        let _ = self
            .console_pg
            .summary_lbl
            .hwnd()
            .SetWindowText("Executing... streaming events...");

        let app = self.clone();
        std::thread::spawn(move || {
            let mut last_flush = Instant::now();
            let mut pending_lines: Vec<String> = Vec::new();
            let mut pending_actions = Vec::new();
            let mut latest_pct: Option<f32> = None;
            let mut latest_summary = None;
            let mut finished: Option<RunResult> = None;

            loop {
                match rx.recv_timeout(Duration::from_millis(40)) {
                    Ok(ev) => match ev {
                        RunnerEvent::Started { command_line } => pending_lines.push(format!("> {command_line}")),
                        RunnerEvent::LogLine(line) => pending_lines.push(line),
                        RunnerEvent::FileAction(rec) => {
                            pending_lines.push(format!("[{}] {} -> {}", rec.kind.label(), rec.path, rec.detail));
                            pending_actions.push(rec);
                        }
                        RunnerEvent::Progress { percent, .. } => latest_pct = Some(percent),
                        RunnerEvent::Error(err) => pending_lines.push(format!("[ERROR] {err}")),
                        RunnerEvent::Summary(sum) => latest_summary = Some(sum),
                        RunnerEvent::Finished(res) => {
                            finished = Some(*res);
                            break;
                        }
                    },
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }

                if last_flush.elapsed() >= Duration::from_millis(45)
                    && (!pending_lines.is_empty()
                        || !pending_actions.is_empty()
                        || latest_pct.is_some()
                        || latest_summary.is_some())
                {
                    let lines_batch = std::mem::take(&mut pending_lines);
                    let actions_batch = std::mem::take(&mut pending_actions);
                    let pct_opt = latest_pct.take();
                    let sum_opt = latest_summary.take();
                    let app2 = app.clone();
                    app.wnd.run_ui_thread(move || {
                        app2.apply_runner_batch(lines_batch, actions_batch, pct_opt, sum_opt);
                        Ok(())
                    });
                    last_flush = Instant::now();
                }
            }

            if !pending_lines.is_empty()
                || !pending_actions.is_empty()
                || latest_pct.is_some()
                || latest_summary.is_some()
                || finished.is_some()
            {
                let app2 = app.clone();
                app.wnd.run_ui_thread(move || {
                    app2.apply_runner_batch(pending_lines, pending_actions, latest_pct, latest_summary);
                    if let Some(res) = finished {
                        app2.finish_runner(res);
                    }
                    Ok(())
                });
            }
        });
        true
    }

    fn apply_runner_batch(
        &self,
        lines: Vec<String>,
        actions: Vec<android2rust_runner::FileActionRecord>,
        pct: Option<f32>,
        summary: Option<android2rust_runner::RunSummary>,
    ) {
        let mut st = self.state.lock().unwrap();
        for l in lines {
            st.push_log_line(l);
        }
        let filter = ActionFilter::from_index(self.console_pg.filter_combo.items().selected_index());
        if !actions.is_empty() {
            self.console_pg.actions_list.set_redraw(false);
            for rec in actions {
                if filter.matches(&rec) {
                    let sz = rec.size_bytes.map(format_bytes).unwrap_or_else(|| "-".to_string());
                    let _ = self.console_pg.actions_list.items().add(
                        &[rec.kind.label(), &sz, &rec.path, &rec.detail],
                        None,
                        (),
                    );
                }
                st.live_file_actions.push(rec);
            }
            self.console_pg.actions_list.set_redraw(true);
        }

        if let Some(p) = pct {
            st.live_progress_pct = p;
            self.console_pg.progress.set_position(p.clamp(0.0, 100.0) as u32);
        }
        if let Some(s) = summary {
            st.live_summary = s;
        }

        let tail_start = st.live_log_lines.len().saturating_sub(600);
        let tail: String = st
            .live_log_lines
            .iter()
            .skip(tail_start)
            .cloned()
            .collect::<Vec<_>>()
            .join("\r\n");
        let _ = self.console_pg.raw_log_edit.set_text(&tail);
        let len = tail.encode_utf16().count() as i32;
        self.console_pg.raw_log_edit.set_selection(len, len);

        let sum_txt = format!(
            "Dev: {} | Props: {} | Pkgs: {} | Bytes: {} | Errs: {}",
            st.live_summary.devices_seen,
            st.live_summary.properties_seen,
            st.live_summary.packages_seen,
            format_bytes(st.live_summary.bytes_processed),
            st.live_summary.errors_seen,
        );
        let _ = self.console_pg.summary_lbl.hwnd().SetWindowText(&sum_txt);
        self.refresh_status_bar(&st);
    }

    fn finish_runner(&self, res: RunResult) {
        let next_start_idx = {
            let mut st = self.state.lock().unwrap();
            st.is_running = false;
            st.cancel_token = None;
            if res.status_info.is_success {
                st.live_progress_pct = 100.0;
            }
            self.console_pg.progress.set_position(st.live_progress_pct as u32);
            st.live_summary = res.summary.clone();
            st.status_message = format!(
                "{} finished: {} ({} records)",
                res.tool.label(),
                res.status_info.short_label,
                res.file_actions.len()
            );

            let sum_txt = format!(
                "{} | Records {} | Bytes {} | {}",
                res.status_info.short_label,
                res.file_actions.len(),
                format_bytes(res.summary.bytes_processed),
                format_duration(res.duration_secs)
            );
            let _ = self.console_pg.summary_lbl.hwnd().SetWindowText(&sum_txt);

            let entry = RunHistoryEntry {
                id: format!("run-{}", Utc::now().timestamp_millis()),
                timestamp: res.ended_at.clone(),
                job_name: res.job_name.clone(),
                source: res.source.clone(),
                destination: res.destination.clone(),
                dry_run: res.dry_run,
                command_line: res.command_line.clone(),
                exit_code: res.exit_code,
                exit_label: res.status_info.short_label.clone(),
                is_success: res.status_info.is_success,
                duration_secs: res.duration_secs,
                records_count: res.file_actions.len() as u64,
                error_count: res.errors.len() as u64,
                bytes_processed: res.summary.bytes_processed,
                summary_text: res.status_info.summary.clone(),
            };
            if let Ok(updated) = st.store.append_history(entry) {
                st.run_history = updated;
            }

            let was_ok = res.status_info.is_success;
            let code = res.exit_code;
            let recs = res.file_actions.len();
            st.last_result = Some(res);

            let mut next_idx_opt = None;
            if st.batch_running
                && let Some(idx) = st.active_batch_idx
            {
                if idx < st.batch_items.len() {
                    st.batch_items[idx].status = if was_ok {
                        BatchStatus::Succeeded(code)
                    } else {
                        BatchStatus::Failed(code)
                    };
                    st.batch_items[idx].note = format!("Code {code} | {recs} recs");
                }
                if !was_ok && st.batch_stop_on_error {
                    st.batch_running = false;
                    st.active_batch_idx = None;
                    st.status_message = format!("Batch stopped at item #{} (exit code {code}).", idx + 1);
                } else if idx + 1 < st.batch_items.len() {
                    next_idx_opt = Some(idx + 1);
                } else {
                    st.batch_running = false;
                    st.active_batch_idx = None;
                    st.status_message = "Batch queue completed.".to_string();
                }
            }
            self.refresh_status_bar(&st);
            next_idx_opt
        };

        self.refresh_batch_and_history_lists();
        if let Some(next_idx) = next_start_idx {
            self.start_batch_from(next_idx);
        }
    }

    fn export_report(&self, fmt: ReportFormat) {
        let res_opt = self.state.lock().unwrap().last_result.clone();
        let Some(res) = res_opt else {
            let _ = self.wnd.hwnd().MessageBox(
                "Run, dry-run, or inspect an artifact first before exporting an audit report.",
                "No Run Result",
                co::MB::ICONINFORMATION,
            );
            return;
        };

        let target = if fmt == ReportFormat::All {
            pick_folder(
                self.wnd.hwnd(),
                "Select Folder for HTML + JSON + Markdown Report Bundle",
            )
            .ok()
            .flatten()
            .map(std::path::PathBuf::from)
        } else {
            pick_save_file(
                self.wnd.hwnd(),
                "Save Android2Rust Audit Report",
                "android2rust_report.html",
                "html",
                &[("HTML Report", "*.html")],
            )
            .ok()
            .flatten()
        };

        if let Some(path) = target {
            match write_report(&res, fmt, &path) {
                Ok(files) => {
                    let mut st = self.state.lock().unwrap();
                    st.status_message = format!(
                        "Saved report: {}",
                        files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    self.refresh_status_bar(&st);
                }
                Err(e) => {
                    let _ = self
                        .wnd
                        .hwnd()
                        .MessageBox(&e.to_string(), "Report Error", co::MB::ICONERROR);
                }
            }
        }
    }

    fn save_current_profile(&self) {
        let mut st = self.state.lock().unwrap();
        let mut name = st.job.name.trim().to_string();
        if name.is_empty() {
            name = format!("Profile_{}", Utc::now().format("%Y%m%d_%H%M%S"));
            st.job.name = name.clone();
        }
        let desc = st.job.description.clone();
        let job_clone = st.job.clone();
        match st.store.upsert_profile(&name, &desc, job_clone) {
            Ok(updated) => {
                st.profiles = updated;
                st.status_message = format!("Saved profile '{name}'.");
                self.refresh_status_bar(&st);
            }
            Err(e) => {
                let _ = self
                    .wnd
                    .hwnd()
                    .MessageBox(&e.to_string(), "Profile Error", co::MB::ICONERROR);
            }
        }
        drop(st);
        self.refresh_profile_combo();
    }

    fn import_recipe_dialog(&self) {
        if let Ok(Some(path)) = pick_open_file(
            self.wnd.hwnd(),
            "Import Android2Rust Recipe (.a2r)",
            &[("Android2Rust Recipe (*.a2r)", "*.a2r"), ("All Files", "*.*")],
        ) {
            match std::fs::read(&path)
                .map_err(anyhow::Error::from)
                .and_then(|b| parse_recipe(&b))
            {
                Ok((job, warnings)) => {
                    {
                        let mut st = self.state.lock().unwrap();
                        st.job = job;
                        st.refresh_derived();
                        st.status_message = if warnings.is_empty() {
                            format!("Imported .a2r: {}", path.display())
                        } else {
                            format!("Imported .a2r with {} warning(s).", warnings.len())
                        };
                    }
                    self.sync_job_to_controls();
                }
                Err(e) => {
                    let _ = self
                        .wnd
                        .hwnd()
                        .MessageBox(&e.to_string(), "Import Error", co::MB::ICONERROR);
                }
            }
        }
    }

    fn export_text_artifact(&self, title: &str, default_name: &str, ext: &str, filter: (&str, &str), content: String) {
        if let Ok(Some(path)) = pick_save_file(self.wnd.hwnd(), title, default_name, ext, &[filter]) {
            match std::fs::write(&path, content) {
                Ok(_) => {
                    let mut st = self.state.lock().unwrap();
                    st.status_message = format!("Exported {}", path.display());
                    self.refresh_status_bar(&st);
                }
                Err(e) => {
                    let _ = self
                        .wnd
                        .hwnd()
                        .MessageBox(&e.to_string(), "Export Error", co::MB::ICONERROR);
                }
            }
        }
    }

    fn register_events(&self) {
        let self2 = self.clone();
        self.wnd.on().wm_create(move |_| {
            {
                let op_labels: Vec<String> = AndroidOperation::ALL.iter().map(|o| o.label().to_string()).collect();
                let _ = self2.op_combo.items().add(&op_labels);

                let st = self2.state.lock().unwrap();
                let preset_names: Vec<String> = st.presets.iter().map(|p| p.name.clone()).collect();
                let _ = self2.preset_combo.items().add(&preset_names);
                self2.preset_combo.items().select(Some(0));
            }
            self2.suppress_sync.store(true, Ordering::SeqCst);
            let _ = self2.designer.sch_name.set_text("Android2Rust_DailyPull");
            let _ = self2.designer.sch_time.set_text("02:00");
            self2.designer.sch_highest.set_check(true);
            let _ = self2.batch_pg.code_edit.set_text("DEVICE_UNAUTHORIZED");
            self2.batch_pg.chk_stop_err.set_check(true);
            self2.suppress_sync.store(false, Ordering::SeqCst);

            self2.refresh_profile_combo();
            self2.sync_job_to_controls();
            self2.refresh_batch_and_history_lists();
            self2.layout_active_tab_page(0);
            Ok(0)
        });

        let self2 = self.clone();
        self.wnd.on().wm_size(move |_| {
            let idx = self2.tab.items().selected().map(|i| i.index()).unwrap_or(0);
            self2.layout_active_tab_page(idx);
            Ok(())
        });

        let self2 = self.clone();
        self.tab.on().tcn_sel_change(move || {
            let idx = self2.tab.items().selected().map(|i| i.index()).unwrap_or(0);
            self2.layout_active_tab_page(idx);
            Ok(())
        });

        let wire_edit = |ed: &gui::Edit| {
            let app = self.clone();
            ed.on().en_change(move || {
                app.sync_controls_to_job();
                Ok(())
            });
        };
        let wire_chk = |cb: &gui::CheckBox| {
            let app = self.clone();
            cb.on().bn_clicked(move || {
                app.sync_controls_to_job();
                Ok(())
            });
        };
        let wire_cmb = |cm: &gui::ComboBox| {
            let app = self.clone();
            cm.on().cbn_sel_change(move || {
                app.sync_controls_to_job();
                Ok(())
            });
        };

        wire_cmb(&self.op_combo);
        wire_cmb(&self.adb_pg.reboot_combo);
        wire_edit(&self.serial_edit);
        wire_edit(&self.src_edit);
        {
            let app = self.clone();
            self.tgt_edit.on().en_change(move || {
                if app.suppress_sync.load(Ordering::SeqCst) {
                    return Ok(());
                }
                let is_fastboot = app
                    .op_combo
                    .items()
                    .selected_index()
                    .and_then(|idx| AndroidOperation::ALL.get(idx as usize))
                    .is_some_and(|op| op.default_tool() == android2rust_core::ToolFamily::Fastboot);
                if is_fastboot {
                    let val = app.tgt_edit.text().unwrap_or_default();
                    app.suppress_sync.store(true, Ordering::SeqCst);
                    let _ = app.fastboot_pg.partition.set_text(&val);
                    app.suppress_sync.store(false, Ordering::SeqCst);
                }
                app.sync_controls_to_job();
                Ok(())
            });
        }
        wire_edit(&self.designer.job_name);
        wire_edit(&self.designer.job_desc);

        for ed in [&self.designer.sch_name, &self.designer.sch_time] {
            let app = self.clone();
            ed.on().en_change(move || {
                let cmd = app.state.lock().unwrap().cached_command.clone();
                app.update_schtasks_preview(&cmd);
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.designer.sch_cadence.on().cbn_sel_change(move || {
                let cmd = app.state.lock().unwrap().cached_command.clone();
                app.update_schtasks_preview(&cmd);
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.designer.sch_highest.on().bn_clicked(move || {
                let cmd = app.state.lock().unwrap().cached_command.clone();
                app.update_schtasks_preview(&cmd);
                Ok(())
            });
        }

        for ed in [
            &self.adb_pg.user_id,
            &self.transfer_pg.compression,
            &self.transfer_pg.bak_packages,
            &self.transfer_pg.log_buffers,
            &self.transfer_pg.log_format,
            &self.transfer_pg.log_max_lines,
            &self.transfer_pg.log_filters,
            &self.fastboot_pg.slot,
            &self.forensics_pg.max_entries,
            &self.forensics_pg.extra_args,
        ] {
            wire_edit(ed);
        }
        {
            let app = self.clone();
            self.fastboot_pg.partition.on().en_change(move || {
                if app.suppress_sync.load(Ordering::SeqCst) {
                    return Ok(());
                }
                let is_fastboot = app
                    .op_combo
                    .items()
                    .selected_index()
                    .and_then(|idx| AndroidOperation::ALL.get(idx as usize))
                    .is_some_and(|op| op.default_tool() == android2rust_core::ToolFamily::Fastboot);
                if is_fastboot {
                    let val = app.fastboot_pg.partition.text().unwrap_or_default();
                    app.suppress_sync.store(true, Ordering::SeqCst);
                    let _ = app.tgt_edit.set_text(&val);
                    app.suppress_sync.store(false, Ordering::SeqCst);
                }
                app.sync_controls_to_job();
                Ok(())
            });
        }

        {
            let app = self.clone();
            self.adb_pg.third_party.on().bn_clicked(move || {
                if app.adb_pg.third_party.is_checked() && app.adb_pg.system_only.is_checked() {
                    app.suppress_sync.store(true, Ordering::SeqCst);
                    app.adb_pg.system_only.set_check(false);
                    app.suppress_sync.store(false, Ordering::SeqCst);
                }
                app.sync_controls_to_job();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.adb_pg.system_only.on().bn_clicked(move || {
                if app.adb_pg.system_only.is_checked() && app.adb_pg.third_party.is_checked() {
                    app.suppress_sync.store(true, Ordering::SeqCst);
                    app.adb_pg.third_party.set_check(false);
                    app.suppress_sync.store(false, Ordering::SeqCst);
                }
                app.sync_controls_to_job();
                Ok(())
            });
        }

        for cb in [
            &self.adb_pg.show_apk_path,
            &self.adb_pg.show_installer,
            &self.adb_pg.show_uid,
            &self.adb_pg.reinstall,
            &self.adb_pg.allow_downgrade,
            &self.adb_pg.grant_perms,
            &self.adb_pg.keep_data,
            &self.transfer_pg.preserve_ts,
            &self.transfer_pg.sync_newer,
            &self.transfer_pg.bak_apk,
            &self.transfer_pg.bak_obb,
            &self.transfer_pg.bak_shared,
            &self.transfer_pg.bak_all,
            &self.transfer_pg.bak_system,
            &self.transfer_pg.log_dump,
            &self.transfer_pg.log_clear,
            &self.fastboot_pg.skip_reboot,
            &self.fastboot_pg.wipe_userdata,
            &self.fastboot_pg.disable_verity,
            &self.fastboot_pg.disable_verification,
            &self.forensics_pg.sha256,
            &self.forensics_pg.manifest_perms,
            &self.forensics_pg.sqlite_tables,
            &self.forensics_pg.ab_tar,
        ] {
            wire_chk(cb);
        }

        // File & Folder Pickers
        {
            let app = self.clone();
            self.btn_src_file.on().bn_clicked(move || {
                if let Ok(Some(path)) = pick_open_file(
                    app.wnd.hwnd(),
                    "Select APK, .ab Backup, Image, SQLite DB, or Log",
                    &[
                        ("Android Artifacts", "*.apk;*.ab;*.img;*.zip;*.db;*.xml;*.log"),
                        ("All Files", "*.*"),
                    ],
                ) {
                    let _ = app.src_edit.set_text(&path.display().to_string());
                    app.sync_controls_to_job();
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_src_dir.on().bn_clicked(move || {
                if let Ok(Some(path)) = pick_folder(app.wnd.hwnd(), "Select Source / Extraction Folder") {
                    let _ = app.src_edit.set_text(&path);
                    app.sync_controls_to_job();
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_tgt_dir.on().bn_clicked(move || {
                if let Ok(Some(path)) = pick_folder(app.wnd.hwnd(), "Select Target / Output Folder") {
                    let _ = app.tgt_edit.set_text(&path);
                    app.sync_controls_to_job();
                }
                Ok(())
            });
        }

        // Presets & Profiles
        {
            let app = self.clone();
            self.btn_apply_preset.on().bn_clicked(move || {
                if let Some(idx) = app.preset_combo.items().selected_index() {
                    let mut st = app.state.lock().unwrap();
                    if let Some(p) = st.presets.get(idx as usize).cloned() {
                        st.apply_preset_preserving_paths(p.job);
                        st.status_message = format!("Applied preset '{}'.", p.name);
                    }
                    drop(st);
                    app.sync_job_to_controls();
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_load_prof.on().bn_clicked(move || {
                if let Some(idx) = app.profile_combo.items().selected_index() {
                    let mut st = app.state.lock().unwrap();
                    if let Some(prof) = st.profiles.get(idx as usize).cloned() {
                        st.job = prof.job;
                        st.refresh_derived();
                        st.status_message = format!("Loaded profile '{}'.", prof.name);
                    }
                    drop(st);
                    app.sync_job_to_controls();
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_save_prof.on().bn_clicked(move || {
                app.save_current_profile();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_del_prof.on().bn_clicked(move || {
                if let Some(idx) = app.profile_combo.items().selected_index() {
                    let mut st = app.state.lock().unwrap();
                    if let Some(prof) = st.profiles.get(idx as usize).cloned()
                        && let Ok((_, updated)) = st.store.delete_profile(&prof.id)
                    {
                        st.profiles = updated;
                        st.status_message = format!("Deleted profile '{}'.", prof.name);
                        app.refresh_status_bar(&st);
                    }
                    drop(st);
                    app.refresh_profile_combo();
                }
                Ok(())
            });
        }

        // Parse CLI & Copy schtasks
        {
            let app = self.clone();
            self.designer.btn_parse_cmd.on().bn_clicked(move || {
                let raw = app.designer.import_cmd.text().unwrap_or_default();
                let parsed = parse_command_line(&raw);
                {
                    let mut st = app.state.lock().unwrap();
                    st.job = parsed.job;
                    st.refresh_derived();
                    st.status_message = if parsed.unrecognized_tokens.is_empty() {
                        "Parsed command line into Designer.".to_string()
                    } else {
                        format!(
                            "Parsed command with {} unrecognized token(s).",
                            parsed.unrecognized_tokens.len()
                        )
                    };
                }
                app.sync_job_to_controls();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.designer.btn_copy_sch.on().bn_clicked(move || {
                let txt = app.designer.sch_preview.text().unwrap_or_default();
                if copy_to_clipboard(&txt) {
                    let mut st = app.state.lock().unwrap();
                    st.status_message = "Copied schtasks command to clipboard.".to_string();
                    app.refresh_status_bar(&st);
                }
                Ok(())
            });
        }

        // Execution Buttons
        {
            let app = self.clone();
            self.btn_dry_run.on().bn_clicked(move || {
                app.trigger_dry_run();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_run_job.on().bn_clicked(move || {
                app.trigger_execute();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_queue_add.on().bn_clicked(move || {
                {
                    let mut st = app.state.lock().unwrap();
                    st.add_current_to_batch();
                    app.refresh_status_bar(&st);
                }
                app.refresh_batch_and_history_lists();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_stop_job.on().bn_clicked(move || {
                let mut st = app.state.lock().unwrap();
                if let Some(tok) = &st.cancel_token {
                    tok.cancel();
                }
                st.batch_running = false;
                st.status_message = "Cancellation requested...".to_string();
                app.refresh_status_bar(&st);
                Ok(())
            });
        }

        // Live console filter & exports
        {
            let app = self.clone();
            self.console_pg.filter_combo.on().cbn_sel_change(move || {
                app.refresh_action_list();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.console_pg.btn_copy_log.on().bn_clicked(move || {
                let txt = {
                    let st = app.state.lock().unwrap();
                    st.live_log_lines.iter().cloned().collect::<Vec<_>>().join("\n")
                };
                if copy_to_clipboard(&txt) {
                    let mut st = app.state.lock().unwrap();
                    st.status_message = "Copied console log to clipboard.".to_string();
                    app.refresh_status_bar(&st);
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.console_pg.btn_export_html.on().bn_clicked(move || {
                app.export_report(ReportFormat::Html);
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.console_pg.btn_export_all.on().bn_clicked(move || {
                app.export_report(ReportFormat::All);
                Ok(())
            });
        }

        // Batch Queue & History
        {
            let app = self.clone();
            self.batch_pg.btn_add.on().bn_clicked(move || {
                {
                    let mut st = app.state.lock().unwrap();
                    st.add_current_to_batch();
                    app.refresh_status_bar(&st);
                }
                app.refresh_batch_and_history_lists();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.batch_pg.chk_stop_err.on().bn_clicked(move || {
                let checked = app.batch_pg.chk_stop_err.is_checked();
                app.state.lock().unwrap().batch_stop_on_error = checked;
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.batch_pg.btn_clear_queue.on().bn_clicked(move || {
                {
                    let mut st = app.state.lock().unwrap();
                    if !st.is_running {
                        st.batch_items.clear();
                    }
                }
                app.refresh_batch_and_history_lists();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.batch_pg.btn_remove.on().bn_clicked(move || {
                if let Some(sel) = app.batch_pg.batch_list.items().iter_selected().next() {
                    let idx = sel.index() as usize;
                    let mut st = app.state.lock().unwrap();
                    if !st.is_running && idx < st.batch_items.len() {
                        st.batch_items.remove(idx);
                    }
                }
                app.refresh_batch_and_history_lists();
                Ok(())
            });
        }
        for (button, dry_mode) in [
            (&self.batch_pg.btn_dry_queue, true),
            (&self.batch_pg.btn_run_queue, false),
        ] {
            let app = self.clone();
            button.on().bn_clicked(move || {
                let first_destructive = {
                    let st = app.state.lock().unwrap();
                    if st.is_running || st.batch_items.is_empty() {
                        return Ok(());
                    }
                    if dry_mode {
                        None
                    } else {
                        st.batch_items.iter().find_map(|item| {
                            let mut live = item.job.clone();
                            live.dry_run = false;
                            live.is_destructive().then_some((
                                live.destructive_reasons().join(", "),
                                live.serial,
                                live.source_path,
                                live.target_path,
                            ))
                        })
                    }
                };

                let effective_dry = if let Some((reasons, serial, source_path, target_path)) = first_destructive {
                    let msg_txt = format!(
                        "Batch queue contains destructive Android operation(s): {reasons}\n\nFirst destructive item:\nSerial: {serial}\nSource/Image: {source_path}\nTarget/Partition: {target_path}\n\nClick YES to Execute the live batch queue.\nClick NO to run the entire queue in safe Dry-Run mode instead.\nClick CANCEL to abort."
                    );
                    match app.wnd.hwnd().MessageBox(
                        &msg_txt,
                        "Confirm Destructive Batch Queue",
                        co::MB::YESNOCANCEL | co::MB::ICONWARNING,
                    ) {
                        Ok(co::DLGID::YES) => false,
                        Ok(co::DLGID::NO) => true,
                        _ => return Ok(()),
                    }
                } else {
                    dry_mode
                };

                {
                    let mut st = app.state.lock().unwrap();
                    if st.is_running || st.batch_items.is_empty() {
                        return Ok(());
                    }
                    for item in &mut st.batch_items {
                        item.status = BatchStatus::Pending;
                        item.note = "Pending".to_string();
                    }
                    st.batch_running = true;
                    st.batch_dry_run = effective_dry;
                    st.active_batch_idx = None;
                }
                app.start_batch_from(0);
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.batch_pg.btn_reload_hist.on().bn_clicked(move || {
                if let Some(sel) = app.batch_pg.hist_list.items().iter_selected().next() {
                    let idx = sel.index() as usize;
                    let mut st = app.state.lock().unwrap();
                    if let Some(entry) = st.run_history.get(idx).cloned() {
                        st.job = parse_command_line(&entry.command_line).job;
                        st.refresh_derived();
                        st.status_message = format!("Reloaded command from '{}'.", entry.job_name);
                    }
                    drop(st);
                    app.sync_job_to_controls();
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.batch_pg.btn_clear_hist.on().bn_clicked(move || {
                {
                    let mut st = app.state.lock().unwrap();
                    let _ = st.store.clear_history();
                    st.run_history.clear();
                }
                app.refresh_batch_and_history_lists();
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.batch_pg.btn_decode.on().bn_clicked(move || {
                let code_str = app.batch_pg.code_edit.text().unwrap_or_default();
                let info = decode_status_code(&code_str);
                let _ = app
                    .batch_pg
                    .decode_lbl
                    .hwnd()
                    .SetWindowText(&format!("{} | {}", info.short_label, info.summary));
                Ok(())
            });
        }

        // Bottom Command Bar
        {
            let app = self.clone();
            self.btn_copy_cmd.on().bn_clicked(move || {
                let cmd = app.state.lock().unwrap().cached_command.clone();
                if copy_to_clipboard(&cmd) {
                    let mut st = app.state.lock().unwrap();
                    st.status_message = "Copied command line to clipboard.".to_string();
                    app.refresh_status_bar(&st);
                }
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_exp_recipe.on().bn_clicked(move || {
                let content = serialize_recipe(&app.state.lock().unwrap().job);
                app.export_text_artifact(
                    "Export .a2r Recipe",
                    "android_job.a2r",
                    "a2r",
                    ("Android2Rust Recipe (*.a2r)", "*.a2r"),
                    content,
                );
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_exp_bat.on().bn_clicked(move || {
                let content = build_batch_script(&app.state.lock().unwrap().job);
                app.export_text_artifact(
                    "Export .bat Script",
                    "android_job.bat",
                    "bat",
                    ("Batch Script (*.bat)", "*.bat"),
                    content,
                );
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_exp_ps1.on().bn_clicked(move || {
                let content = build_powershell_script(&app.state.lock().unwrap().job);
                app.export_text_artifact(
                    "Export PowerShell Script",
                    "android_job.ps1",
                    "ps1",
                    ("PowerShell Script (*.ps1)", "*.ps1"),
                    content,
                );
                Ok(())
            });
        }
        {
            let app = self.clone();
            self.btn_exp_sh.on().bn_clicked(move || {
                let content = build_shell_script(&app.state.lock().unwrap().job);
                app.export_text_artifact(
                    "Export POSIX Shell Script",
                    "android_job.sh",
                    "sh",
                    ("Shell Script (*.sh)", "*.sh"),
                    content,
                );
                Ok(())
            });
        }

        // Native Menu Bar Commands
        let wire_menu = |id: u16, handler: Box<dyn Fn(&Win32App)>| {
            let app = self.clone();
            self.wnd.on().wm_command_acc_menu(id, move || {
                handler(&app);
                Ok(())
            });
        };
        wire_menu(IDM_IMPORT_RECIPE, Box::new(|a| a.import_recipe_dialog()));
        wire_menu(
            IDM_EXPORT_RECIPE,
            Box::new(|a| {
                let content = serialize_recipe(&a.state.lock().unwrap().job);
                a.export_text_artifact(
                    "Export .a2r Recipe",
                    "android_job.a2r",
                    "a2r",
                    ("Android2Rust Recipe (*.a2r)", "*.a2r"),
                    content,
                );
            }),
        );
        wire_menu(
            IDM_EXPORT_BAT,
            Box::new(|a| {
                let content = build_batch_script(&a.state.lock().unwrap().job);
                a.export_text_artifact(
                    "Export .bat Script",
                    "android_job.bat",
                    "bat",
                    ("Batch Script (*.bat)", "*.bat"),
                    content,
                );
            }),
        );
        wire_menu(
            IDM_EXPORT_PS1,
            Box::new(|a| {
                let content = build_powershell_script(&a.state.lock().unwrap().job);
                a.export_text_artifact(
                    "Export PowerShell Script",
                    "android_job.ps1",
                    "ps1",
                    ("PowerShell Script (*.ps1)", "*.ps1"),
                    content,
                );
            }),
        );
        wire_menu(
            IDM_EXPORT_SH,
            Box::new(|a| {
                let content = build_shell_script(&a.state.lock().unwrap().job);
                a.export_text_artifact(
                    "Export Shell Script",
                    "android_job.sh",
                    "sh",
                    ("Shell Script (*.sh)", "*.sh"),
                    content,
                );
            }),
        );
        wire_menu(IDM_REPORT_HTML, Box::new(|a| a.export_report(ReportFormat::Html)));
        wire_menu(IDM_REPORT_ALL, Box::new(|a| a.export_report(ReportFormat::All)));
        wire_menu(
            IDM_EXIT,
            Box::new(|a| {
                let _ = a.wnd.hwnd().DestroyWindow();
            }),
        );
        wire_menu(
            IDM_RESET_JOB,
            Box::new(|a| {
                {
                    let mut st = a.state.lock().unwrap();
                    st.job = AndroidJob::default();
                    st.refresh_derived();
                    st.status_message = "Reset to default Device Inventory job.".to_string();
                }
                a.sync_job_to_controls();
            }),
        );
        wire_menu(
            IDM_COPY_CMD,
            Box::new(|a| {
                let cmd = a.state.lock().unwrap().cached_command.clone();
                if copy_to_clipboard(&cmd) {
                    let mut st = a.state.lock().unwrap();
                    st.status_message = "Copied command line to clipboard.".to_string();
                    a.refresh_status_bar(&st);
                }
            }),
        );
        wire_menu(IDM_SAVE_PROFILE, Box::new(|a| a.save_current_profile()));
        wire_menu(
            IDM_QUEUE_ADD,
            Box::new(|a| {
                {
                    let mut st = a.state.lock().unwrap();
                    st.add_current_to_batch();
                    a.refresh_status_bar(&st);
                }
                a.refresh_batch_and_history_lists();
            }),
        );
        wire_menu(IDM_DRY_RUN, Box::new(|a| a.trigger_dry_run()));
        wire_menu(IDM_RUN_JOB, Box::new(|a| a.trigger_execute()));
        wire_menu(
            IDM_STOP_JOB,
            Box::new(|a| {
                let mut st = a.state.lock().unwrap();
                if let Some(tok) = &st.cancel_token {
                    tok.cancel();
                }
                st.batch_running = false;
                st.status_message = "Cancellation requested...".to_string();
                a.refresh_status_bar(&st);
            }),
        );
        wire_menu(
            IDM_ABOUT,
            Box::new(|a| {
                let st = a.state.lock().unwrap();
                let adb = st
                    .env
                    .adb_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "Not found".to_string());
                let fb = st
                    .env
                    .fastboot_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "Not found".to_string());
                let msg_txt = format!(
                    "Android2Rust Management & Forensics Console v{}\n\n\
                     Zero-GPU Native Win32 Edition (WinSafe 0.0.29)\n\
                     Part of the GUAP Ecosystem (guap.ca) • Apache-2.0\n\n\
                     ADB: {}\n\
                     Fastboot: {}\n\
                     Config Store: {}",
                    env!("CARGO_PKG_VERSION"),
                    adb,
                    fb,
                    st.env.config_dir.display()
                );
                let _ = a
                    .wnd
                    .hwnd()
                    .MessageBox(&msg_txt, "About Android2Rust Win32", co::MB::ICONINFORMATION);
            }),
        );
    }
}
