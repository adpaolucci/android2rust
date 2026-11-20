use android2rust_core::{AndroidJob, AndroidOperation, RebootTarget, ScheduleCadence};
use android2rust_report::ReportFormat;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTab {
    Designer,
    AdbPackages,
    TransferLogcat,
    FastbootPartitions,
    ForensicsArtifacts,
    LiveConsole,
    BatchQueue,
    HistoryReports,
}

impl WorkspaceTab {
    pub fn title(self) -> &'static str {
        match self {
            Self::Designer => "Job Designer",
            Self::AdbPackages => "ADB & Packages",
            Self::TransferLogcat => "Transfer & Logcat",
            Self::FastbootPartitions => "Fastboot & Flash",
            Self::ForensicsArtifacts => "Forensic Inspector",
            Self::LiveConsole => "Live Console & Records",
            Self::BatchQueue => "Batch Queue",
            Self::HistoryReports => "History & Reports",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::Designer,
            Self::AdbPackages,
            Self::TransferLogcat,
            Self::FastbootPartitions,
            Self::ForensicsArtifacts,
            Self::LiveConsole,
            Self::BatchQueue,
            Self::HistoryReports,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    ConfirmDestructive,
    ImportCommand,
    SaveProfile,
    TaskScheduler,
    StatusCodeReference,
    About,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionFilter {
    All,
    DevicesPackages,
    TransfersForensics,
    Errors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleSubTab {
    ParsedRecords,
    RawLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchItemStatus {
    Pending,
    Running,
    Succeeded(i32),
    Failed(i32),
}

#[derive(Debug, Clone)]
pub struct BatchQueueItem {
    pub job: AndroidJob,
    pub status: BatchItemStatus,
    pub summary_note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportChoice {
    Auto,
    Usb,
    Emulator,
    Serial,
}

impl TransportChoice {
    pub const ALL: &'static [Self] = &[Self::Auto, Self::Usb, Self::Emulator, Self::Serial];
}

impl fmt::Display for TransportChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "Auto (Use Serial if set)"),
            Self::Usb => write!(f, "USB Only (-d)"),
            Self::Emulator => write!(f, "Emulator Only (-e)"),
            Self::Serial => write!(f, "Explicit Serial (-s)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CadenceChoice(pub ScheduleCadence);

impl CadenceChoice {
    pub const ALL: &'static [Self] = &[
        Self(ScheduleCadence::Daily),
        Self(ScheduleCadence::Weekly),
        Self(ScheduleCadence::Hourly),
        Self(ScheduleCadence::OnStart),
        Self(ScheduleCadence::OnLogon),
    ];
}

impl fmt::Display for CadenceChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ScheduleCadence::Daily => write!(f, "DAILY"),
            ScheduleCadence::Weekly => write!(f, "WEEKLY"),
            ScheduleCadence::Hourly => write!(f, "HOURLY"),
            ScheduleCadence::OnStart => write!(f, "ONSTART"),
            ScheduleCadence::OnLogon => write!(f, "ONLOGON"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    // Navigation & Theme
    SelectTab(WorkspaceTab),
    ToggleDarkMode,
    OpenModal(ActiveModal),
    CloseModal,

    // Target Bar
    OperationChanged(AndroidOperation),
    TransportChanged(TransportChoice),
    SerialChanged(String),
    SourceChanged(String),
    TargetChanged(String),
    BrowseSourceFile,
    BrowseSourceDir,
    BrowseTargetDir,

    // Execution
    TriggerDryRun,
    TriggerExecute,
    ConfirmDestructiveExecute,
    DryRunPendingInstead,
    StopExecution,
    PollRunner,

    // Presets & Profiles
    ApplyPreset(usize),
    LoadProfile(usize),
    DeleteProfile(String),
    SaveProfileNameChanged(String),
    SaveProfileDescChanged(String),
    ConfirmSaveProfile,
    ResetDefaultJob,

    // Designer & Exports
    JobNameChanged(String),
    JobDescChanged(String),
    ImportCmdTextChanged(String),
    ApplyImportCmd,
    ImportRecipeFile,
    ExportRecipeFile,
    ExportBatchFile,
    ExportPs1File,
    ExportShellFile,
    CopyCommandLine,
    CopySchtasksCmd,
    TaskNameChanged(String),
    TaskCadenceChanged(CadenceChoice),
    TaskStartTimeChanged(String),
    TaskDaysChanged(String),
    TaskRunHighestToggled(bool),
    TaskTargetChanged(String),
    StatusCodeInputChanged(String),
    SelectQuickStatusCode(String),

    // ADB & Packages
    ToggleThirdPartyOnly(bool),
    ToggleSystemOnly(bool),
    ToggleShowApkPath(bool),
    ToggleShowInstaller(bool),
    ToggleShowUid(bool),
    ToggleReinstall(bool),
    ToggleAllowDowngrade(bool),
    ToggleGrantPerms(bool),
    ToggleKeepData(bool),
    UserIdChanged(String),
    RebootTargetChanged(RebootTarget),

    // Transfer, Backup & Logcat
    TogglePreserveTimestamps(bool),
    ToggleSyncNewer(bool),
    CompressionChanged(String),
    ToggleBackupApk(bool),
    ToggleBackupObb(bool),
    ToggleBackupShared(bool),
    ToggleBackupAll(bool),
    ToggleBackupSystem(bool),
    BackupPackagesChanged(String),
    LogcatBuffersChanged(String),
    LogcatFormatChanged(String),
    LogcatFiltersChanged(String),
    LogcatMaxLinesChanged(String),
    ToggleLogcatDump(bool),
    ToggleLogcatClear(bool),

    // Fastboot
    PartitionChanged(String),
    SlotChanged(String),
    ToggleSkipReboot(bool),
    ToggleWipeUserdata(bool),
    ToggleDisableVerity(bool),
    ToggleDisableVerification(bool),

    // Forensics
    ToggleForensicSha256(bool),
    ToggleForensicPerms(bool),
    ToggleForensicSqlite(bool),
    ToggleForensicTar(bool),
    ForensicMaxEntriesChanged(String),
    ExtraArgsChanged(String),

    // Live Console & Diff
    SwitchConsoleSubTab(ConsoleSubTab),
    SetActionFilter(ActionFilter),
    ActionSearchChanged(String),
    LogSearchChanged(String),
    CopyLogToClipboard,
    ExportReport(ReportFormat),

    // Batch Queue
    AddCurrentToQueue,
    ToggleStopOnError(bool),
    StartBatchQueue(bool),
    MoveQueueUp(usize),
    MoveQueueDown(usize),
    LoadQueueItem(usize),
    DuplicateQueueItem(usize),
    RemoveQueueItem(usize),
    ClearBatchQueue,

    // History
    SelectHistory(usize),
    ReloadHistoryCommand(usize),
    ClearHistory,
}
