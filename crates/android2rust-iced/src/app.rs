use crate::LaunchArgs;
use crate::message::{
    ActionFilter, ActiveModal, BatchItemStatus, BatchQueueItem, ConsoleSubTab, Message, TransportChoice, WorkspaceTab,
};
use crate::views;
use android2rust_core::{
    AndroidJob, AndroidOperation, JobPreset, ProfileStore, RunHistoryEntry, SavedProfile, ScheduleSpec, ToolFamily,
    TransportMode, ValidationFinding, ValidationSeverity, build_batch_script, build_powershell_script,
    build_shell_script, builtin_presets, format_command_line, parse_command_line, parse_recipe, quote_windows_arg,
    serialize_recipe, tokenize_windows_cmdline, validate_job,
};
use android2rust_report::{ReportFormat, write_report};
use android2rust_runner::{
    CancelToken, EnvironmentInfo, FileActionRecord, RunResult, RunSummary, RunnerEvent, detect_environment,
    spawn_job_runner,
};
use chrono::Utc;
use iced::widget::{button, column, container, mouse_area, pick_list, row, rule, space, stack, text, text_input};
use iced::{Alignment, Color, Element, Font, Length, Subscription, Task, Theme};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Duration;

pub const MAX_LOG_BUFFER_LINES: usize = 50_000;

pub struct App {
    pub env: EnvironmentInfo,
    pub job: AndroidJob,

    // Draft text fields
    pub user_id_text: String,
    pub backup_packages_text: String,
    pub logcat_buffers_text: String,
    pub logcat_filters_text: String,
    pub logcat_max_lines_text: String,
    pub forensic_max_entries_text: String,
    pub extra_args_text: String,

    // Derived cache
    pub cached_command: String,
    pub findings: Vec<ValidationFinding>,

    // Navigation & theme
    pub dark_mode: bool,
    pub active_tab: WorkspaceTab,
    pub active_modal: ActiveModal,

    // Presets & persistence
    pub presets: Vec<JobPreset>,
    pub store: ProfileStore,
    pub profiles: Vec<SavedProfile>,
    pub run_history: Vec<RunHistoryEntry>,
    pub selected_history_idx: Option<usize>,

    // Runner state
    pub is_running: bool,
    pub runner_rx: Option<Receiver<RunnerEvent>>,
    pub cancel_token: Option<CancelToken>,
    pub live_progress_pct: f32,
    pub live_current_file: Option<String>,
    pub live_summary: RunSummary,
    pub live_log_lines: VecDeque<String>,
    pub live_file_actions: Vec<FileActionRecord>,
    pub live_errors: Vec<String>,
    pub last_result: Option<RunResult>,

    // Live console controls
    pub console_subtab: ConsoleSubTab,
    pub action_filter: ActionFilter,
    pub action_search: String,
    pub log_search: String,

    // Batch Queue
    pub batch_items: Vec<BatchQueueItem>,
    pub batch_running: bool,
    pub batch_dry_run_mode: bool,
    pub batch_stop_on_error: bool,
    pub active_batch_index: Option<usize>,

    // Modals
    pub pending_destructive_job: Option<AndroidJob>,
    pub pending_destructive_batch: bool,
    pub import_cmd_text: String,
    pub save_profile_name: String,
    pub save_profile_desc: String,
    pub task_sched_name: String,
    pub task_sched_target: String,
    pub task_sched_spec: ScheduleSpec,
    pub status_code_input: String,

    pub status_message: String,
}

impl App {
    pub fn new(launch: LaunchArgs) -> (Self, Task<Message>) {
        let env = detect_environment();
        let presets = builtin_presets();
        let store = ProfileStore::default_store();
        let profiles = store.load_profiles().unwrap_or_default();
        let run_history = store.load_history().unwrap_or_default();

        let mut job = presets.first().map(|p| p.job.clone()).unwrap_or_default();
        let mut status_msg = if env.adb_available {
            "Ready — select an operation, target path/artifact, or preset.".to_string()
        } else {
            "ADB/Fastboot not on PATH (Builder, Dry-Run, & Pure-Rust Forensics ready).".to_string()
        };

        if let Some(recipe_path) = &launch.recipe {
            match std::fs::read(recipe_path)
                .map_err(anyhow::Error::from)
                .and_then(|b| parse_recipe(&b))
            {
                Ok((parsed, _)) => {
                    job = parsed;
                    status_msg = format!("Loaded .a2r recipe: {}", recipe_path.display());
                }
                Err(e) => {
                    status_msg = format!("Failed loading .a2r recipe: {e}");
                }
            }
        } else if let Some(prof_name) = &launch.profile
            && let Ok(Some(found)) = store.find_profile(prof_name)
        {
            job = found.job;
            status_msg = format!("Loaded profile '{}'.", found.name);
        }

        if let Some(s) = launch.source {
            job.source_path = s;
        }
        if let Some(t) = launch.target {
            job.target_path = t.clone();
            if job.tool == ToolFamily::Fastboot {
                job.fastboot_opts.partition = t;
            }
        }
        if let Some(ser) = launch.serial {
            job.serial = ser;
        }

        let mut app = Self {
            env,
            user_id_text: String::new(),
            backup_packages_text: String::new(),
            logcat_buffers_text: String::new(),
            logcat_filters_text: String::new(),
            logcat_max_lines_text: String::new(),
            forensic_max_entries_text: String::new(),
            extra_args_text: String::new(),
            cached_command: String::new(),
            findings: Vec::new(),
            job: AndroidJob::default(),

            dark_mode: true,
            active_tab: WorkspaceTab::Designer,
            active_modal: ActiveModal::None,

            presets,
            store,
            profiles,
            run_history,
            selected_history_idx: None,

            is_running: false,
            runner_rx: None,
            cancel_token: None,
            live_progress_pct: 0.0,
            live_current_file: None,
            live_summary: RunSummary::default(),
            live_log_lines: VecDeque::new(),
            live_file_actions: Vec::new(),
            live_errors: Vec::new(),
            last_result: None,

            console_subtab: ConsoleSubTab::ParsedRecords,
            action_filter: ActionFilter::All,
            action_search: String::new(),
            log_search: String::new(),

            batch_items: Vec::new(),
            batch_running: false,
            batch_dry_run_mode: false,
            batch_stop_on_error: true,
            active_batch_index: None,

            pending_destructive_job: None,
            pending_destructive_batch: false,
            import_cmd_text: String::new(),
            save_profile_name: String::new(),
            save_profile_desc: String::new(),
            task_sched_name: "Android2Rust_DailyPull".to_string(),
            task_sched_target: String::new(),
            task_sched_spec: ScheduleSpec::default(),
            status_code_input: "DEVICE_UNAUTHORIZED".to_string(),

            status_message: status_msg,
        };
        app.set_job(job);
        (app, Task::none())
    }

    pub fn title(&self) -> String {
        if self.is_running {
            format!("Android2Rust ({:.0}%) - {}", self.live_progress_pct, self.job.name)
        } else {
            "Android2Rust Management & Forensics Console (Iced Cross-Platform)".to_string()
        }
    }

    pub fn theme(&self) -> Theme {
        if self.dark_mode { Theme::Dark } else { Theme::Light }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if self.is_running {
            iced::time::every(Duration::from_millis(60)).map(|_| Message::PollRunner)
        } else {
            Subscription::none()
        }
    }

    pub fn set_job(&mut self, job: AndroidJob) {
        self.job = job;
        self.user_id_text = self.job.package_opts.user_id.map(|v| v.to_string()).unwrap_or_default();
        self.backup_packages_text = join_tokens(&self.job.backup_opts.packages);
        self.logcat_buffers_text = join_tokens(&self.job.logcat_opts.buffers);
        self.logcat_filters_text = join_tokens(&self.job.logcat_opts.filter_specs);
        self.logcat_max_lines_text = self
            .job
            .logcat_opts
            .max_lines
            .map(|v| v.to_string())
            .unwrap_or_default();
        self.forensic_max_entries_text = self.job.forensic_opts.max_entries.to_string();
        self.extra_args_text = join_tokens(&self.job.extra_args);
        self.refresh_derived();
    }

    pub fn set_job_preserving_paths(&mut self, mut next_job: AndroidJob) {
        if next_job.source_path.trim().is_empty() && !self.job.source_path.trim().is_empty() {
            next_job.source_path = self.job.source_path.clone();
        }
        if next_job.target_path.trim().is_empty() && !self.job.target_path.trim().is_empty() {
            next_job.target_path = self.job.target_path.clone();
        }
        if next_job.tool == ToolFamily::Fastboot && !next_job.target_path.trim().is_empty() {
            next_job.fastboot_opts.partition = next_job.target_path.trim().to_string();
        }
        if next_job.serial.trim().is_empty() && !self.job.serial.trim().is_empty() {
            next_job.serial = self.job.serial.clone();
        }
        self.set_job(next_job);
    }

    pub fn refresh_derived(&mut self) {
        self.cached_command = format_command_line(&self.job);
        self.findings = validate_job(&self.job);
    }

    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == ValidationSeverity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == ValidationSeverity::Warning)
            .count()
    }

    fn current_transport_choice(&self) -> TransportChoice {
        match self.job.transport {
            TransportMode::Auto => TransportChoice::Auto,
            TransportMode::Usb => TransportChoice::Usb,
            TransportMode::Emulator => TransportChoice::Emulator,
            TransportMode::Serial(_) | TransportMode::TransportId(_) => TransportChoice::Serial,
        }
    }

    fn start_execution(&mut self, job: AndroidJob) -> bool {
        let errs: Vec<_> = validate_job(&job)
            .into_iter()
            .filter(|f| f.severity == ValidationSeverity::Error)
            .collect();
        if !errs.is_empty() {
            self.status_message = format!("Validation error: {}", errs[0].message);
            return false;
        }

        self.live_progress_pct = 0.0;
        self.live_current_file = None;
        self.live_summary = RunSummary::default();
        self.live_log_lines.clear();
        self.live_file_actions.clear();
        self.live_errors.clear();
        self.last_result = None;
        self.active_tab = WorkspaceTab::LiveConsole;

        let (rx, cancel) = spawn_job_runner(job.clone(), None);
        self.runner_rx = Some(rx);
        self.cancel_token = Some(cancel);
        self.is_running = true;
        self.status_message = format!("Running: {}", format_command_line(&job));
        true
    }

    fn launch_batch_queue(&mut self, dry_mode: bool) {
        if self.is_running || self.batch_items.is_empty() {
            return;
        }
        for item in &mut self.batch_items {
            item.status = BatchItemStatus::Pending;
            item.summary_note = "Pending".to_string();
        }
        self.batch_running = true;
        self.batch_dry_run_mode = dry_mode;
        self.start_batch_item(0);
    }

    fn start_batch_item(&mut self, mut idx: usize) {
        while idx < self.batch_items.len() {
            self.active_batch_index = Some(idx);
            self.batch_items[idx].status = BatchItemStatus::Running;
            self.batch_items[idx].summary_note = "Running...".to_string();
            let mut next_job = self.batch_items[idx].job.clone();
            if self.batch_dry_run_mode {
                next_job = next_job.with_dry_run();
            } else {
                next_job.dry_run = false;
            }
            if self.start_execution(next_job) {
                return;
            }
            self.batch_items[idx].status = BatchItemStatus::Failed(1);
            self.batch_items[idx].summary_note = "Validation Error".to_string();
            if self.batch_stop_on_error {
                self.batch_running = false;
                self.active_batch_index = None;
                return;
            }
            idx += 1;
        }
        self.batch_running = false;
        self.active_batch_index = None;
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SelectTab(tab) => self.active_tab = tab,
            Message::ToggleDarkMode => self.dark_mode = !self.dark_mode,
            Message::OpenModal(modal) => {
                if modal == ActiveModal::TaskScheduler && self.task_sched_target.trim().is_empty() {
                    self.task_sched_target = self.cached_command.clone();
                }
                if modal == ActiveModal::SaveProfile && self.save_profile_name.trim().is_empty() {
                    self.save_profile_name = self.job.name.clone();
                    self.save_profile_desc = self.job.description.clone();
                }
                self.active_modal = modal;
            }
            Message::CloseModal => {
                self.active_modal = ActiveModal::None;
                self.pending_destructive_job = None;
                self.pending_destructive_batch = false;
            }

            Message::OperationChanged(op) => {
                self.job.operation = op;
                self.job.tool = op.default_tool();
                self.refresh_derived();
            }
            Message::TransportChanged(tc) => {
                self.job.transport = match tc {
                    TransportChoice::Auto => TransportMode::Auto,
                    TransportChoice::Usb => TransportMode::Usb,
                    TransportChoice::Emulator => TransportMode::Emulator,
                    TransportChoice::Serial => TransportMode::Serial(self.job.serial.clone()),
                };
                self.refresh_derived();
            }
            Message::SerialChanged(s) => {
                self.job.serial = s;
                if matches!(self.job.transport, TransportMode::Serial(_)) {
                    self.job.transport = TransportMode::Serial(self.job.serial.clone());
                }
                self.refresh_derived();
            }
            Message::SourceChanged(s) => {
                self.job.source_path = s;
                self.refresh_derived();
            }
            Message::TargetChanged(t) => {
                self.job.target_path = t.clone();
                if self.job.tool == ToolFamily::Fastboot {
                    self.job.fastboot_opts.partition = t;
                }
                self.refresh_derived();
            }
            Message::BrowseSourceFile => {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Select Android Artifact, APK, .ab Backup, Image, or DB")
                    .pick_file()
                {
                    self.job.source_path = p.display().to_string();
                    self.refresh_derived();
                }
            }
            Message::BrowseSourceDir => {
                if let Some(p) = pick_folder_dialog(&self.job.source_path, "Select Local Source Folder") {
                    self.job.source_path = p.display().to_string();
                    self.refresh_derived();
                }
            }
            Message::BrowseTargetDir => {
                if let Some(p) = pick_folder_dialog(&self.job.target_path, "Select Local Destination Folder") {
                    self.job.target_path = p.display().to_string();
                    self.refresh_derived();
                }
            }

            Message::TriggerDryRun => {
                if !self.is_running {
                    let _ = self.start_execution(self.job.with_dry_run());
                }
            }
            Message::TriggerExecute => {
                if !self.is_running {
                    let mut live = self.job.clone();
                    live.dry_run = false;
                    if live.is_destructive() {
                        self.pending_destructive_batch = false;
                        self.pending_destructive_job = Some(live);
                        self.active_modal = ActiveModal::ConfirmDestructive;
                    } else {
                        let _ = self.start_execution(live);
                    }
                }
            }
            Message::ConfirmDestructiveExecute => {
                self.active_modal = ActiveModal::None;
                let is_batch = self.pending_destructive_batch;
                self.pending_destructive_batch = false;
                let pending = self.pending_destructive_job.take();
                if is_batch {
                    self.launch_batch_queue(false);
                } else if let Some(job) = pending {
                    let _ = self.start_execution(job);
                }
            }
            Message::DryRunPendingInstead => {
                self.active_modal = ActiveModal::None;
                let is_batch = self.pending_destructive_batch;
                self.pending_destructive_batch = false;
                let pending = self.pending_destructive_job.take();
                if is_batch {
                    self.launch_batch_queue(true);
                } else if let Some(job) = pending {
                    let _ = self.start_execution(job.with_dry_run());
                }
            }
            Message::StopExecution => {
                if let Some(tok) = &self.cancel_token {
                    tok.cancel();
                }
                self.batch_running = false;
                self.status_message = "Cancellation requested...".to_string();
            }
            Message::PollRunner => {
                let mut finished_res: Option<RunResult> = None;
                let mut drained = Vec::new();
                if let Some(rx) = &self.runner_rx {
                    while let Ok(ev) = rx.try_recv() {
                        drained.push(ev);
                    }
                }
                for ev in drained {
                    match ev {
                        RunnerEvent::Started { command_line } => {
                            if self.live_log_lines.len() >= MAX_LOG_BUFFER_LINES {
                                self.live_log_lines.pop_front();
                            }
                            self.live_log_lines.push_back(format!("> {command_line}"));
                        }
                        RunnerEvent::LogLine(line) => {
                            if self.live_log_lines.len() >= MAX_LOG_BUFFER_LINES {
                                self.live_log_lines.pop_front();
                            }
                            self.live_log_lines.push_back(line);
                        }
                        RunnerEvent::FileAction(rec) => {
                            if self.live_log_lines.len() >= MAX_LOG_BUFFER_LINES {
                                self.live_log_lines.pop_front();
                            }
                            self.live_log_lines.push_back(format!(
                                "[{}] {} -> {}",
                                rec.kind.label(),
                                rec.path,
                                rec.detail
                            ));
                            self.live_file_actions.push(rec);
                        }
                        RunnerEvent::Progress { percent, current_file } => {
                            self.live_progress_pct = percent;
                            if current_file.is_some() {
                                self.live_current_file = current_file;
                            }
                        }
                        RunnerEvent::Error(err) => {
                            self.live_errors.push(err.clone());
                            if self.live_log_lines.len() >= MAX_LOG_BUFFER_LINES {
                                self.live_log_lines.pop_front();
                            }
                            self.live_log_lines.push_back(format!("[ERROR] {err}"));
                        }
                        RunnerEvent::Summary(sum) => {
                            self.live_summary = sum;
                        }
                        RunnerEvent::Finished(res) => {
                            finished_res = Some(*res);
                        }
                    }
                }

                if let Some(res) = finished_res {
                    self.is_running = false;
                    self.runner_rx = None;
                    self.cancel_token = None;
                    if res.status_info.is_success {
                        self.live_progress_pct = 100.0;
                    }
                    self.status_message = format!("Finished: {}", res.status_info.short_label);

                    let hist = RunHistoryEntry {
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
                    if let Ok(updated) = self.store.append_history(hist) {
                        self.run_history = updated;
                    }
                    let exit_code = res.exit_code;
                    let is_ok = res.status_info.is_success;
                    self.last_result = Some(res);

                    if self.batch_running
                        && let Some(idx) = self.active_batch_index
                    {
                        if let Some(item) = self.batch_items.get_mut(idx) {
                            item.status = if is_ok {
                                BatchItemStatus::Succeeded(exit_code)
                            } else {
                                BatchItemStatus::Failed(exit_code)
                            };
                            item.summary_note = format!("Code {exit_code}");
                        }
                        let next_idx = idx + 1;
                        if next_idx < self.batch_items.len() && (is_ok || !self.batch_stop_on_error) {
                            self.start_batch_item(next_idx);
                        } else {
                            self.batch_running = false;
                            self.active_batch_index = None;
                        }
                    }
                }
            }

            Message::ApplyPreset(idx) => {
                if let Some(p) = self.presets.get(idx).cloned() {
                    let name = p.name.clone();
                    self.set_job_preserving_paths(p.job);
                    self.status_message = format!("Applied preset '{name}'.");
                }
            }
            Message::LoadProfile(idx) => {
                if let Some(prof) = self.profiles.get(idx).cloned() {
                    self.set_job(prof.job);
                    self.status_message = format!("Loaded profile '{}'.", prof.name);
                }
            }
            Message::DeleteProfile(id) => {
                if let Ok((true, list)) = self.store.delete_profile(&id) {
                    self.profiles = list;
                    self.status_message = format!("Deleted profile '{id}'.");
                }
            }
            Message::SaveProfileNameChanged(s) => self.save_profile_name = s,
            Message::SaveProfileDescChanged(s) => self.save_profile_desc = s,
            Message::ConfirmSaveProfile => {
                if !self.save_profile_name.trim().is_empty()
                    && let Ok(list) =
                        self.store
                            .upsert_profile(&self.save_profile_name, &self.save_profile_desc, self.job.clone())
                {
                    self.profiles = list;
                    self.status_message = format!("Saved profile '{}'.", self.save_profile_name);
                }
                self.active_modal = ActiveModal::None;
            }
            Message::ResetDefaultJob => {
                self.set_job(AndroidJob::default());
                self.status_message = "Reset to default Device Inventory job.".to_string();
            }

            Message::JobNameChanged(s) => {
                self.job.name = s;
                self.refresh_derived();
            }
            Message::JobDescChanged(s) => {
                self.job.description = s;
                self.refresh_derived();
            }
            Message::ImportCmdTextChanged(s) => self.import_cmd_text = s,
            Message::ApplyImportCmd => {
                let parsed = parse_command_line(&self.import_cmd_text);
                let warn_count = parsed.unrecognized_tokens.len();
                self.set_job(parsed.job);
                self.active_modal = ActiveModal::None;
                self.status_message = if warn_count == 0 {
                    "Parsed command line into Designer.".to_string()
                } else {
                    format!("Parsed command ({warn_count} unrecognized token(s)).")
                };
            }
            Message::ImportRecipeFile => {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Import .a2r Recipe File")
                    .add_filter("Android2Rust Recipe", &["a2r", "json"])
                    .pick_file()
                    && let Ok(bytes) = std::fs::read(&path)
                    && let Ok((parsed, _)) = parse_recipe(&bytes)
                {
                    self.set_job(parsed);
                    self.status_message = format!("Imported recipe: {}", path.display());
                }
            }
            Message::ExportRecipeFile => {
                let content = serialize_recipe(&self.job);
                save_text_with_dialog(
                    "Export .a2r Recipe",
                    "android_job.a2r",
                    &[("Android2Rust Recipe", &["a2r"])],
                    &content,
                    &mut self.status_message,
                );
            }
            Message::ExportBatchFile => {
                let content = build_batch_script(&self.job);
                save_text_with_dialog(
                    "Export Windows .bat Script",
                    "android_job.bat",
                    &[("Batch Script", &["bat"])],
                    &content,
                    &mut self.status_message,
                );
            }
            Message::ExportPs1File => {
                let content = build_powershell_script(&self.job);
                save_text_with_dialog(
                    "Export PowerShell Script",
                    "android_job.ps1",
                    &[("PowerShell Script", &["ps1"])],
                    &content,
                    &mut self.status_message,
                );
            }
            Message::ExportShellFile => {
                let content = build_shell_script(&self.job);
                save_text_with_dialog(
                    "Export POSIX Shell Script",
                    "android_job.sh",
                    &[("Shell Script", &["sh"])],
                    &content,
                    &mut self.status_message,
                );
            }
            Message::CopyCommandLine => {
                if set_clipboard_text(&self.cached_command) {
                    self.status_message = "Copied command line to clipboard.".to_string();
                }
            }
            Message::CopySchtasksCmd => {
                let cmd = android2rust_core::build_schtasks_command(
                    &self.task_sched_name,
                    &self.task_sched_target,
                    &self.task_sched_spec,
                );
                if set_clipboard_text(&cmd) {
                    self.status_message = "Copied schtasks command to clipboard.".to_string();
                }
            }
            Message::TaskNameChanged(s) => self.task_sched_name = s,
            Message::TaskCadenceChanged(c) => self.task_sched_spec.cadence = c.0,
            Message::TaskStartTimeChanged(s) => self.task_sched_spec.start_time = s,
            Message::TaskDaysChanged(s) => self.task_sched_spec.days = opt_nonempty(&s),
            Message::TaskRunHighestToggled(b) => self.task_sched_spec.run_highest = b,
            Message::TaskTargetChanged(s) => self.task_sched_target = s,
            Message::StatusCodeInputChanged(s) => self.status_code_input = s,
            Message::SelectQuickStatusCode(s) => self.status_code_input = s,

            Message::ToggleThirdPartyOnly(b) => {
                self.job.package_opts.third_party_only = b;
                if b {
                    self.job.package_opts.system_only = false;
                }
                self.refresh_derived();
            }
            Message::ToggleSystemOnly(b) => {
                self.job.package_opts.system_only = b;
                if b {
                    self.job.package_opts.third_party_only = false;
                }
                self.refresh_derived();
            }
            Message::ToggleShowApkPath(b) => {
                self.job.package_opts.show_apk_path = b;
                self.refresh_derived();
            }
            Message::ToggleShowInstaller(b) => {
                self.job.package_opts.show_installer = b;
                self.refresh_derived();
            }
            Message::ToggleShowUid(b) => {
                self.job.package_opts.show_uid = b;
                self.refresh_derived();
            }
            Message::ToggleReinstall(b) => {
                self.job.package_opts.reinstall = b;
                self.refresh_derived();
            }
            Message::ToggleAllowDowngrade(b) => {
                self.job.package_opts.allow_downgrade = b;
                self.refresh_derived();
            }
            Message::ToggleGrantPerms(b) => {
                self.job.package_opts.grant_permissions = b;
                self.refresh_derived();
            }
            Message::ToggleKeepData(b) => {
                self.job.package_opts.keep_data = b;
                self.refresh_derived();
            }
            Message::UserIdChanged(s) => {
                self.user_id_text = s.clone();
                self.job.package_opts.user_id = s.trim().parse().ok();
                self.refresh_derived();
            }
            Message::RebootTargetChanged(t) => {
                self.job.reboot_target = t;
                self.refresh_derived();
            }

            Message::TogglePreserveTimestamps(b) => {
                self.job.transfer_opts.preserve_timestamps = b;
                self.refresh_derived();
            }
            Message::ToggleSyncNewer(b) => {
                self.job.transfer_opts.sync_only_newer = b;
                self.refresh_derived();
            }
            Message::CompressionChanged(s) => {
                self.job.transfer_opts.compression = opt_nonempty(&s);
                self.refresh_derived();
            }
            Message::ToggleBackupApk(b) => {
                self.job.backup_opts.include_apk = b;
                self.refresh_derived();
            }
            Message::ToggleBackupObb(b) => {
                self.job.backup_opts.include_obb = b;
                self.refresh_derived();
            }
            Message::ToggleBackupShared(b) => {
                self.job.backup_opts.include_shared = b;
                self.refresh_derived();
            }
            Message::ToggleBackupAll(b) => {
                self.job.backup_opts.all_apps = b;
                self.refresh_derived();
            }
            Message::ToggleBackupSystem(b) => {
                self.job.backup_opts.include_system = b;
                self.refresh_derived();
            }
            Message::BackupPackagesChanged(s) => {
                self.backup_packages_text = s.clone();
                self.job.backup_opts.packages = split_tokens(&s);
                self.refresh_derived();
            }
            Message::LogcatBuffersChanged(s) => {
                self.logcat_buffers_text = s.clone();
                self.job.logcat_opts.buffers = split_tokens(&s);
                self.refresh_derived();
            }
            Message::LogcatFormatChanged(s) => {
                self.job.logcat_opts.format = s;
                self.refresh_derived();
            }
            Message::LogcatFiltersChanged(s) => {
                self.logcat_filters_text = s.clone();
                self.job.logcat_opts.filter_specs = split_tokens(&s);
                self.refresh_derived();
            }
            Message::LogcatMaxLinesChanged(s) => {
                self.logcat_max_lines_text = s.clone();
                self.job.logcat_opts.max_lines = s.trim().parse().ok();
                self.refresh_derived();
            }
            Message::ToggleLogcatDump(b) => {
                self.job.logcat_opts.dump_and_exit = b;
                self.refresh_derived();
            }
            Message::ToggleLogcatClear(b) => {
                self.job.logcat_opts.clear_first = b;
                self.refresh_derived();
            }

            Message::PartitionChanged(s) => {
                self.job.fastboot_opts.partition = s.clone();
                if self.job.tool == ToolFamily::Fastboot {
                    self.job.target_path = s;
                }
                self.refresh_derived();
            }
            Message::SlotChanged(s) => {
                self.job.fastboot_opts.slot = opt_nonempty(&s);
                self.refresh_derived();
            }
            Message::ToggleSkipReboot(b) => {
                self.job.fastboot_opts.skip_reboot = b;
                self.refresh_derived();
            }
            Message::ToggleWipeUserdata(b) => {
                self.job.fastboot_opts.wipe_userdata = b;
                self.refresh_derived();
            }
            Message::ToggleDisableVerity(b) => {
                self.job.fastboot_opts.disable_verity = b;
                self.refresh_derived();
            }
            Message::ToggleDisableVerification(b) => {
                self.job.fastboot_opts.disable_verification = b;
                self.refresh_derived();
            }

            Message::ToggleForensicSha256(b) => self.job.forensic_opts.compute_sha256 = b,
            Message::ToggleForensicPerms(b) => self.job.forensic_opts.extract_manifest_permissions = b,
            Message::ToggleForensicSqlite(b) => self.job.forensic_opts.inspect_sqlite_tables = b,
            Message::ToggleForensicTar(b) => self.job.forensic_opts.inspect_ab_tar_entries = b,
            Message::ForensicMaxEntriesChanged(s) => {
                self.forensic_max_entries_text = s.clone();
                if let Ok(n) = s.trim().parse::<usize>() {
                    self.job.forensic_opts.max_entries = n.max(10);
                }
            }
            Message::ExtraArgsChanged(s) => {
                self.extra_args_text = s.clone();
                self.job.extra_args = split_tokens(&s);
                self.refresh_derived();
            }

            Message::SwitchConsoleSubTab(st) => self.console_subtab = st,
            Message::SetActionFilter(af) => self.action_filter = af,
            Message::ActionSearchChanged(s) => self.action_search = s,
            Message::LogSearchChanged(s) => self.log_search = s,
            Message::CopyLogToClipboard => {
                let txt = self.live_log_lines.iter().cloned().collect::<Vec<_>>().join("\n");
                if set_clipboard_text(&txt) {
                    self.status_message = "Copied console log to clipboard.".to_string();
                }
            }
            Message::ExportReport(fmt) => {
                if let Some(res) = &self.last_result {
                    let (title, def_name) = match fmt {
                        ReportFormat::Html => ("Export HTML Audit Report", "android_audit.html"),
                        ReportFormat::Json => ("Export JSON Audit Report", "android_audit.json"),
                        ReportFormat::Markdown => ("Export Markdown Audit Report", "android_audit.md"),
                        ReportFormat::TimelineCsv => ("Export Chronological Timeline (CSV)", "android_timeline.csv"),
                        ReportFormat::TimelineJsonl => {
                            ("Export Chronological Timeline (JSONL)", "android_timeline.jsonl")
                        }
                        ReportFormat::All => ("Export Full Report Bundle (Base Filename)", "android_audit"),
                    };
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title(title)
                        .set_file_name(def_name)
                        .save_file()
                    {
                        match write_report(res, fmt, &path) {
                            Ok(files) => {
                                self.status_message = format!("Exported {} report file(s).", files.len());
                            }
                            Err(e) => self.status_message = format!("Report export failed: {e}"),
                        }
                    }
                }
            }

            Message::AddCurrentToQueue => {
                let mut job = self.job.clone();
                if job.name.trim().is_empty() {
                    job.name = format!("Queued Job #{}", self.batch_items.len() + 1);
                }
                self.batch_items.push(BatchQueueItem {
                    job,
                    status: BatchItemStatus::Pending,
                    summary_note: "Queued".to_string(),
                });
                self.status_message = format!("Added job to Batch Queue ({} items).", self.batch_items.len());
            }
            Message::ToggleStopOnError(b) => self.batch_stop_on_error = b,
            Message::StartBatchQueue(dry_mode) => {
                if !self.is_running && !self.batch_items.is_empty() {
                    if !dry_mode
                        && let Some(first_destr) = self.batch_items.iter().find_map(|item| {
                            let mut live = item.job.clone();
                            live.dry_run = false;
                            live.is_destructive().then_some(live)
                        })
                    {
                        self.pending_destructive_batch = true;
                        self.pending_destructive_job = Some(first_destr);
                        self.active_modal = ActiveModal::ConfirmDestructive;
                    } else {
                        self.launch_batch_queue(dry_mode);
                    }
                }
            }
            Message::MoveQueueUp(idx) => {
                if idx > 0 && idx < self.batch_items.len() {
                    self.batch_items.swap(idx - 1, idx);
                }
            }
            Message::MoveQueueDown(idx) => {
                if idx + 1 < self.batch_items.len() {
                    self.batch_items.swap(idx, idx + 1);
                }
            }
            Message::LoadQueueItem(idx) => {
                if let Some(item) = self.batch_items.get(idx).cloned() {
                    self.set_job(item.job);
                    self.active_tab = WorkspaceTab::Designer;
                }
            }
            Message::DuplicateQueueItem(idx) => {
                if let Some(item) = self.batch_items.get(idx).cloned() {
                    self.batch_items.insert(idx + 1, item);
                }
            }
            Message::RemoveQueueItem(idx) => {
                if !self.is_running && idx < self.batch_items.len() {
                    self.batch_items.remove(idx);
                }
            }
            Message::ClearBatchQueue => {
                if !self.is_running {
                    self.batch_items.clear();
                }
            }

            Message::SelectHistory(idx) => self.selected_history_idx = Some(idx),
            Message::ReloadHistoryCommand(idx) => {
                if let Some(entry) = self.run_history.get(idx).cloned() {
                    self.set_job(parse_command_line(&entry.command_line).job);
                    self.active_tab = WorkspaceTab::Designer;
                }
            }
            Message::ClearHistory => {
                let _ = self.store.clear_history();
                self.run_history.clear();
                self.selected_history_idx = None;
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        let top_toolbar = self.view_top_toolbar();
        let command_bar = self.view_command_bar();
        let sidebar = container(views::sidebar::view_sidebar(self))
            .width(Length::Fixed(250.0))
            .height(Length::Fill)
            .padding(10)
            .style(container::bordered_box);

        let content_area: Element<'_, Message> = match self.active_tab {
            WorkspaceTab::Designer => views::designer::view_designer(self),
            WorkspaceTab::AdbPackages => views::options_tabs::view_adb_packages(self),
            WorkspaceTab::TransferLogcat => views::options_tabs::view_transfer_logcat(self),
            WorkspaceTab::FastbootPartitions => views::options_tabs::view_fastboot_partitions(self),
            WorkspaceTab::ForensicsArtifacts => views::options_tabs::view_forensics_artifacts(self),
            WorkspaceTab::LiveConsole => views::live_console::view_live_console(self),
            WorkspaceTab::BatchQueue => views::batch_queue::view_batch_queue(self),
            WorkspaceTab::HistoryReports => views::history_view::view_history_view(self),
        };

        let center = row![
            sidebar,
            container(content_area)
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(10),
        ]
        .height(Length::Fill);

        let main_layout = column![
            top_toolbar,
            rule::horizontal(1),
            command_bar,
            rule::horizontal(1),
            center,
            rule::horizontal(1),
            self.view_status_bar(),
        ]
        .height(Length::Fill);

        if self.active_modal == ActiveModal::None {
            main_layout.into()
        } else {
            let backdrop = mouse_area(
                container(views::modals::view_modal(self))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.55).into()),
                        ..Default::default()
                    }),
            )
            .on_press(Message::CloseModal);

            stack![main_layout, backdrop].into()
        }
    }

    fn view_top_toolbar(&self) -> Element<'_, Message> {
        let can_run = !self.is_running;
        let can_exec = can_run && self.error_count() == 0;

        let run_label = if self.job.is_destructive() {
            "Run (!)"
        } else {
            "Run Job"
        };
        let run_btn = button(text(run_label).size(13))
            .on_press_maybe(can_exec.then_some(Message::TriggerExecute))
            .style(if self.job.is_destructive() {
                button::danger
            } else {
                button::primary
            });

        let row_controls = row![
            pick_list(
                AndroidOperation::ALL,
                Some(self.job.operation),
                Message::OperationChanged,
            )
            .text_size(12)
            .width(Length::Fixed(215.0)),
            pick_list(
                TransportChoice::ALL,
                Some(self.current_transport_choice()),
                Message::TransportChanged,
            )
            .text_size(12)
            .width(Length::Fixed(165.0)),
            text_input("Serial (-s)", &self.job.serial)
                .on_input(Message::SerialChanged)
                .size(12)
                .width(Length::Fixed(110.0)),
            text_input("Source / Artifact / APK / Image", &self.job.source_path)
                .on_input(Message::SourceChanged)
                .size(12)
                .width(Length::FillPortion(2)),
            button(text("File...").size(12))
                .on_press(Message::BrowseSourceFile)
                .style(button::secondary),
            button(text("Dir...").size(12))
                .on_press(Message::BrowseSourceDir)
                .style(button::secondary),
            text_input("Target / Pkg / Partition", &self.job.target_path)
                .on_input(Message::TargetChanged)
                .size(12)
                .width(Length::FillPortion(2)),
            button(text("Out...").size(12))
                .on_press(Message::BrowseTargetDir)
                .style(button::secondary),
            button(text("Dry-Run").size(12))
                .on_press_maybe(can_run.then_some(Message::TriggerDryRun))
                .style(button::success),
            run_btn,
            button(text("Queue +").size(12))
                .on_press_maybe(can_run.then_some(Message::AddCurrentToQueue))
                .style(button::secondary),
            button(text("Stop").size(12))
                .on_press_maybe(self.is_running.then_some(Message::StopExecution))
                .style(button::danger),
            button(text(if self.dark_mode { "Light" } else { "Dark" }).size(12))
                .on_press(Message::ToggleDarkMode)
                .style(button::secondary),
        ]
        .spacing(5)
        .align_y(Alignment::Center);

        container(row_controls).padding([8, 10]).width(Length::Fill).into()
    }

    fn view_command_bar(&self) -> Element<'_, Message> {
        let bar = row![
            text("CMD:").size(12).font(Font::MONOSPACE),
            text_input("", &self.cached_command)
                .font(Font::MONOSPACE)
                .size(12)
                .width(Length::Fill),
            button(text("Copy").size(12))
                .on_press(Message::CopyCommandLine)
                .style(button::secondary),
            button(text("Import...").size(12))
                .on_press(Message::OpenModal(ActiveModal::ImportCommand))
                .style(button::secondary),
            button(text(".a2r").size(12))
                .on_press(Message::ExportRecipeFile)
                .style(button::secondary),
            button(text(".bat").size(12))
                .on_press(Message::ExportBatchFile)
                .style(button::secondary),
            button(text(".ps1").size(12))
                .on_press(Message::ExportPs1File)
                .style(button::secondary),
            button(text(".sh").size(12))
                .on_press(Message::ExportShellFile)
                .style(button::secondary),
            button(text("Schedule...").size(12))
                .on_press(Message::OpenModal(ActiveModal::TaskScheduler))
                .style(button::secondary),
            button(text("Status Codes").size(12))
                .on_press(Message::OpenModal(ActiveModal::StatusCodeReference))
                .style(button::secondary),
        ]
        .spacing(6)
        .align_y(Alignment::Center);

        container(bar).padding([6, 10]).width(Length::Fill).into()
    }

    fn view_status_bar(&self) -> Element<'_, Message> {
        let diag = if self.error_count() > 0 {
            format!("{} Err / {} Warn", self.error_count(), self.warning_count())
        } else if self.warning_count() > 0 {
            format!("{} Warn", self.warning_count())
        } else {
            "Config Valid".to_string()
        };

        let run_seg = if self.is_running {
            format!("RUNNING ({:.0}%)", self.live_progress_pct)
        } else if let Some(res) = &self.last_result {
            format!("Last: {}", res.status_info.short_label)
        } else {
            "Idle".to_string()
        };

        let env_badge = if self.env.adb_available {
            "Iced 0.14 | ADB + Forensics Ready"
        } else {
            "Iced 0.14 | Offline Forensics & Builder Ready"
        };

        let vsep = || container(rule::vertical(1)).height(Length::Fixed(16.0));
        let bar = row![
            text(&self.status_message).size(12).width(Length::Fill),
            vsep(),
            text(diag).size(12),
            vsep(),
            text(run_seg).size(12),
            vsep(),
            text(env_badge).size(12),
            space::horizontal().width(Length::Fixed(4.0)),
        ]
        .spacing(10)
        .height(Length::Shrink)
        .align_y(Alignment::Center);

        container(bar)
            .padding([5, 10])
            .width(Length::Fill)
            .height(Length::Shrink)
            .style(container::bordered_box)
            .into()
    }
}

fn pick_folder_dialog(current_input: &str, title: &str) -> Option<PathBuf> {
    let mut dlg = rfd::FileDialog::new().set_title(title);
    let trimmed = current_input.trim().trim_matches('"').trim();
    if !trimmed.is_empty() {
        let p = PathBuf::from(trimmed);
        if p.is_dir() {
            dlg = dlg.set_directory(&p);
        } else if let Some(parent) = p.parent()
            && parent.is_dir()
        {
            dlg = dlg.set_directory(parent);
        }
    }
    dlg.pick_folder()
}

fn save_text_with_dialog(
    title: &str,
    default_name: &str,
    filters: &[(&str, &[&str])],
    content: &str,
    status_out: &mut String,
) {
    let mut dlg = rfd::FileDialog::new().set_title(title).set_file_name(default_name);
    for (name, exts) in filters {
        dlg = dlg.add_filter(*name, exts);
    }
    if let Some(path) = dlg.save_file() {
        match std::fs::write(&path, content) {
            Ok(_) => *status_out = format!("Exported {}", path.display()),
            Err(e) => *status_out = format!("Export failed: {e}"),
        }
    }
}

pub fn split_tokens(raw: &str) -> Vec<String> {
    tokenize_windows_cmdline(&raw.replace([',', ';', '\n', '\r'], " "))
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn join_tokens(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| quote_windows_arg(t))
        .collect::<Vec<_>>()
        .join(" ")
}

fn opt_nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

pub fn set_clipboard_text(text: &str) -> bool {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        return cb.set_text(text.to_string()).is_ok();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_application_preserves_paths_and_destructive_guard_opens_modal() {
        let (mut app, _) = App::new(LaunchArgs {
            source: Some("boot.img".to_string()),
            target: Some("boot".to_string()),
            serial: Some("R58M123".to_string()),
            ..Default::default()
        });

        let flash_idx = app.presets.iter().position(|p| p.id == "fastboot-flash-image").unwrap();
        let _ = app.update(Message::ApplyPreset(flash_idx));
        assert_eq!(app.job.source_path, "boot.img");
        assert_eq!(app.job.serial, "R58M123");
        assert!(app.job.is_destructive());

        let _ = app.update(Message::TriggerExecute);
        assert_eq!(app.active_modal, ActiveModal::ConfirmDestructive);
        assert!(!app.is_running);
    }

    #[test]
    fn command_import_and_batch_queue_actions_work() {
        let (mut app, _) = App::new(LaunchArgs::default());
        let _ = app.update(Message::ImportCmdTextChanged(
            r#"adb -s XYZ999 pull -a "/sdcard/DCIM" "D:\Backup""#.to_string(),
        ));
        let _ = app.update(Message::ApplyImportCmd);
        assert_eq!(app.job.operation, AndroidOperation::Pull);
        assert_eq!(app.job.serial, "XYZ999");

        let _ = app.update(Message::AddCurrentToQueue);
        assert_eq!(app.batch_items.len(), 1);
    }

    #[test]
    fn live_batch_queue_guards_destructive_and_handles_validation_errors() {
        let (mut app, _) = App::new(LaunchArgs {
            source: Some("boot.img".to_string()),
            target: Some("boot".to_string()),
            ..Default::default()
        });
        let flash_idx = app.presets.iter().position(|p| p.id == "fastboot-flash-image").unwrap();
        let _ = app.update(Message::ApplyPreset(flash_idx));
        let _ = app.update(Message::AddCurrentToQueue);

        let _ = app.update(Message::StartBatchQueue(false));
        assert_eq!(app.active_modal, ActiveModal::ConfirmDestructive);
        assert!(app.pending_destructive_batch);
        assert!(!app.is_running);

        // Queue with validation error (missing image file) marks Failed and clears batch_running
        let _ = app.update(Message::CloseModal);
        app.batch_items[0].job.source_path.clear();
        let _ = app.update(Message::StartBatchQueue(true));
        assert_eq!(app.batch_items[0].status, BatchItemStatus::Failed(1));
        assert!(!app.batch_running);
        assert!(!app.is_running);
    }
}
