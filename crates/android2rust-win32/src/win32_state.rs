use android2rust_core::{
    AndroidJob, JobPreset, ProfileStore, RunHistoryEntry, SavedProfile, ToolFamily, ValidationFinding,
    ValidationSeverity, builtin_presets, format_command_line, parse_recipe, quote_windows_arg, read_recipe_bounded,
    tokenize_windows_cmdline, validate_job,
};
use android2rust_runner::{CancelToken, EnvironmentInfo, FileActionRecord, RunResult, RunSummary, detect_environment};
use std::collections::VecDeque;

pub const MAX_LOG_LINES: usize = 25_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchStatus {
    Pending,
    Running,
    Succeeded(i32),
    Failed(i32),
}

impl BatchStatus {
    pub fn label(self) -> String {
        match self {
            Self::Pending => "Pending".to_string(),
            Self::Running => "Running...".to_string(),
            Self::Succeeded(c) => format!("OK ({c})"),
            Self::Failed(c) => format!("FAIL ({c})"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchItem {
    pub job: AndroidJob,
    pub status: BatchStatus,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionFilter {
    All,
    DevicesPackages,
    TransfersForensics,
    Errors,
}

impl ActionFilter {
    pub fn from_index(idx: Option<u32>) -> Self {
        match idx {
            Some(1) => Self::DevicesPackages,
            Some(2) => Self::TransfersForensics,
            Some(3) => Self::Errors,
            _ => Self::All,
        }
    }

    pub fn matches(self, rec: &FileActionRecord) -> bool {
        match self {
            Self::All => true,
            Self::DevicesPackages => rec.kind.is_device_or_pkg(),
            Self::TransfersForensics => rec.kind.is_transfer_or_forensic(),
            Self::Errors => rec.kind.is_error(),
        }
    }
}

pub struct Win32State {
    pub env: EnvironmentInfo,
    pub job: AndroidJob,
    pub cached_command: String,
    pub findings: Vec<ValidationFinding>,
    pub presets: Vec<JobPreset>,
    pub store: ProfileStore,
    pub profiles: Vec<SavedProfile>,
    pub run_history: Vec<RunHistoryEntry>,

    pub is_running: bool,
    pub cancel_token: Option<CancelToken>,
    pub live_progress_pct: f32,
    pub live_summary: RunSummary,
    pub live_log_lines: VecDeque<String>,
    pub live_file_actions: Vec<FileActionRecord>,
    pub last_result: Option<RunResult>,

    pub batch_items: Vec<BatchItem>,
    pub next_batch_id: u64,
    pub batch_running: bool,
    pub batch_dry_run: bool,
    pub batch_stop_on_error: bool,
    pub active_batch_idx: Option<usize>,

    pub status_message: String,
}

impl Win32State {
    pub fn new(launch: &crate::LaunchArgs) -> Self {
        let env = detect_environment();
        let presets = builtin_presets();
        let store = ProfileStore::default_store();
        let profiles = store.load_profiles().unwrap_or_default();
        let run_history = store.load_history().unwrap_or_default();

        let mut job = presets.first().map(|p| p.job.clone()).unwrap_or_default();
        let mut status = if env.adb_available {
            "Ready — select operation, target/artifact, or preset.".to_string()
        } else {
            "ADB not on PATH (Dry-Run & Offline Forensics ready).".to_string()
        };

        if let Some(recipe_path) = &launch.recipe {
            match read_recipe_bounded(recipe_path).and_then(|b| parse_recipe(&b)) {
                Ok((parsed, _)) => {
                    job = parsed;
                    status = format!("Loaded .a2r: {}", recipe_path.display());
                }
                Err(e) => {
                    status = format!("Failed loading .a2r: {e}");
                }
            }
        } else if let Some(prof_name) = &launch.profile
            && let Ok(Some(found)) = store.find_profile(prof_name)
        {
            job = found.job;
            status = format!("Loaded profile '{}'.", found.name);
        }

        if let Some(s) = &launch.source {
            job.source_path = s.clone();
        }
        if let Some(t) = &launch.target {
            job.target_path = t.clone();
            if job.tool == ToolFamily::Fastboot {
                job.fastboot_opts.partition = t.clone();
            }
        }
        if let Some(ser) = &launch.serial {
            job.serial = ser.clone();
        }

        let mut st = Self {
            env,
            cached_command: format_command_line(&job),
            findings: validate_job(&job),
            job,
            presets,
            store,
            profiles,
            run_history,
            is_running: false,
            cancel_token: None,
            live_progress_pct: 0.0,
            live_summary: RunSummary::default(),
            live_log_lines: VecDeque::new(),
            live_file_actions: Vec::new(),
            last_result: None,
            batch_items: Vec::new(),
            next_batch_id: 1,
            batch_running: false,
            batch_dry_run: false,
            batch_stop_on_error: true,
            active_batch_idx: None,
            status_message: status,
        };
        st.refresh_derived();
        st
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

    pub fn apply_preset_preserving_paths(&mut self, mut preset_job: AndroidJob) {
        if preset_job.source_path.trim().is_empty() && !self.job.source_path.trim().is_empty() {
            preset_job.source_path = self.job.source_path.clone();
        }
        if preset_job.target_path.trim().is_empty() && !self.job.target_path.trim().is_empty() {
            preset_job.target_path = self.job.target_path.clone();
        }
        if preset_job.tool == ToolFamily::Fastboot && !preset_job.target_path.trim().is_empty() {
            preset_job.fastboot_opts.partition = preset_job.target_path.trim().to_string();
        }
        if preset_job.serial.trim().is_empty() && !self.job.serial.trim().is_empty() {
            preset_job.serial = self.job.serial.clone();
        }
        self.job = preset_job;
        self.refresh_derived();
    }

    pub fn push_log_line(&mut self, line: String) {
        if self.live_log_lines.len() >= MAX_LOG_LINES {
            self.live_log_lines.pop_front();
        }
        self.live_log_lines.push_back(line);
    }

    pub fn add_current_to_batch(&mut self) {
        let mut job = self.job.clone();
        if job.name.trim().is_empty() {
            job.name = format!("Queued Job #{}", self.next_batch_id);
        }
        self.next_batch_id += 1;
        self.batch_items.push(BatchItem {
            job,
            status: BatchStatus::Pending,
            note: "Queued".to_string(),
        });
        self.status_message = format!("Added job to Batch Queue ({} items).", self.batch_items.len());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win32_state_preserves_paths_when_applying_preset() {
        let mut st = Win32State::new(&crate::LaunchArgs {
            source: Some("boot.img".to_string()),
            target: Some("init_boot".to_string()),
            serial: Some("R58M123".to_string()),
            ..Default::default()
        });
        let flash = st
            .presets
            .iter()
            .find(|p| p.id == "fastboot-flash-image")
            .unwrap()
            .job
            .clone();
        st.apply_preset_preserving_paths(flash);
        assert_eq!(st.job.source_path, "boot.img");
        assert_eq!(st.job.serial, "R58M123");
        assert_eq!(st.job.fastboot_opts.partition, "init_boot");
        assert!(st.job.is_destructive());
        assert!(st.cached_command.contains("flash init_boot boot.img"));
    }
}
