#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod win32_app;
#[cfg(windows)]
mod win32_dialogs;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod win32_state;

use android2rust_core::init_logging;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct LaunchArgs {
    pub source: Option<String>,
    pub target: Option<String>,
    pub serial: Option<String>,
    pub recipe: Option<PathBuf>,
    pub profile: Option<String>,
}

pub fn parse_launch_args_from<I>(args: I) -> LaunchArgs
where
    I: IntoIterator<Item = String>,
{
    let mut out = LaunchArgs::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--source" => {
                if let Some(s) = iter.next() {
                    out.source = Some(s);
                }
            }
            "--target" | "--dest" => {
                if let Some(t) = iter.next() {
                    out.target = Some(t);
                }
            }
            "--serial" => {
                if let Some(s) = iter.next() {
                    out.serial = Some(s);
                }
            }
            "--recipe" => {
                if let Some(r) = iter.next() {
                    out.recipe = Some(PathBuf::from(r));
                }
            }
            "--profile" => {
                if let Some(p) = iter.next() {
                    out.profile = Some(p);
                }
            }
            "--help" | "-h" => {
                println!(
                    "android2rust-win32 [--source PATH] [--target TARGET] [--serial SERIAL] [--recipe FILE] [--profile NAME]\n\
                     Launch the native Win32/WinSafe Android2Rust Management & Forensics Console."
                );
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other
                if !other.starts_with('-') && other.to_ascii_lowercase().ends_with(".a2r") && out.recipe.is_none() =>
            {
                out.recipe = Some(PathBuf::from(other));
            }
            _ => {}
        }
    }
    out
}

fn main() {
    let _ = init_logging("warn", None);
    let launch_args = parse_launch_args_from(std::env::args().skip(1));

    #[cfg(windows)]
    {
        if let Err(err) = win32_app::run(launch_args) {
            eprintln!("android2rust-win32 fatal error: {err}");
            std::process::exit(1);
        }
    }

    #[cfg(not(windows))]
    {
        let _ = launch_args;
        eprintln!("android2rust-win32 is a Windows-native Win32 binary. Run `android2rust-iced` on Linux/macOS.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_launch_args_and_positional_recipe() {
        let parsed = parse_launch_args_from(
            [
                "--source",
                r"C:\Apps\demo.apk",
                "--serial",
                "R58M123",
                "audit.a2r",
                "--profile",
                "nightly",
            ]
            .into_iter()
            .map(str::to_string),
        );
        assert_eq!(parsed.source.as_deref(), Some(r"C:\Apps\demo.apk"));
        assert_eq!(parsed.serial.as_deref(), Some("R58M123"));
        assert_eq!(parsed.recipe, Some(PathBuf::from("audit.a2r")));
        assert_eq!(parsed.profile.as_deref(), Some("nightly"));
    }
}
