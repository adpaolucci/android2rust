use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub os: String,
    pub is_windows: bool,
    pub adb_available: bool,
    pub adb_path: Option<PathBuf>,
    pub adb_version: Option<String>,
    pub fastboot_available: bool,
    pub fastboot_path: Option<PathBuf>,
    pub fastboot_version: Option<String>,
    pub config_dir: PathBuf,
}

pub fn detect_environment() -> EnvironmentInfo {
    let is_windows = cfg!(target_os = "windows");
    let adb_path = find_adb_executable();
    let fastboot_path = find_fastboot_executable();
    let adb_version = adb_path.as_deref().and_then(query_tool_version);
    let fastboot_version = fastboot_path.as_deref().and_then(query_tool_version);
    let config_dir = dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("android2rust");

    EnvironmentInfo {
        os: std::env::consts::OS.to_string(),
        is_windows,
        adb_available: adb_path.is_some(),
        adb_path,
        adb_version,
        fastboot_available: fastboot_path.is_some(),
        fastboot_path,
        fastboot_version,
        config_dir,
    }
}

pub fn find_adb_executable() -> Option<PathBuf> {
    find_platform_tool("adb")
}

pub fn find_fastboot_executable() -> Option<PathBuf> {
    find_platform_tool("fastboot")
}

fn find_platform_tool(base: &str) -> Option<PathBuf> {
    let candidates: Vec<String> = if cfg!(target_os = "windows") {
        vec![format!("{base}.exe"), base.to_string()]
    } else {
        vec![base.to_string()]
    };

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for bin in &candidates {
                let p = dir.join(bin);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }

    let mut sdk_roots = Vec::new();
    for env_key in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
        if let Some(val) = std::env::var_os(env_key) {
            sdk_roots.push(PathBuf::from(val).join("platform-tools"));
        }
    }
    if cfg!(target_os = "windows") {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            sdk_roots.push(PathBuf::from(local).join("Android").join("Sdk").join("platform-tools"));
        }
    } else if let Some(home) = dirs::home_dir() {
        sdk_roots.push(home.join("Android").join("Sdk").join("platform-tools"));
        sdk_roots.push(home.join("Library").join("Android").join("sdk").join("platform-tools"));
    }

    for dir in sdk_roots {
        for bin in &candidates {
            let p = dir.join(bin);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn query_tool_version(bin: &std::path::Path) -> Option<String> {
    let mut cmd = Command::new(bin);
    cmd.arg("--version");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string)
}
