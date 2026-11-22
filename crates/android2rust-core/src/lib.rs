#![forbid(unsafe_code)]

pub mod command;
pub mod forensics;
pub mod format;
pub mod logging;
pub mod model;
pub mod parser;
pub mod presets;
pub mod profiles;
pub mod recipe;
pub mod status_code;
pub mod validation;

pub use command::{
    ScheduleCadence, ScheduleSpec, build_args, build_batch_script, build_powershell_script, build_schtasks_command,
    build_shell_script, format_command_line, quote_posix_arg, quote_windows_arg,
};
pub use forensics::{ArtifactKind, ForensicEntry, ForensicReport, TimelineEvent, inspect_artifact};
pub use format::{encode_hex_lower, format_bytes, format_duration};
pub use logging::init_logging;
pub use model::{
    AndroidJob, AndroidOperation, BackupOptions, CaseMetadata, FastbootOptions, ForensicOptions, LogcatOptions,
    PackageOptions, RebootTarget, ToolFamily, TransferOptions, TransportMode,
};
pub use parser::{ParseResult, parse_command_line, tokenize_windows_cmdline};
pub use presets::{JobPreset, builtin_presets, find_preset};
pub use profiles::{ProfileStore, RunHistoryEntry, SavedProfile};
pub use recipe::{parse_recipe, serialize_recipe};
pub use status_code::{StatusCodeInfo, StatusSeverity, decode_exit_code, decode_status_code};
pub use validation::{ValidationFinding, ValidationSeverity, validate_job};
