#![forbid(unsafe_code)]

pub mod env;
pub mod output_parser;
pub mod runner;

pub use env::{EnvironmentInfo, detect_environment, find_adb_executable, find_fastboot_executable};
pub use output_parser::{AndroidOutputParser, FileActionKind, FileActionRecord, ParsedLineOutcome, RunSummary};
pub use runner::{CancelToken, RunResult, RunnerEvent, run_job_blocking, spawn_job_runner};
