#![forbid(unsafe_code)]
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod message;
mod views;

use android2rust_core::init_logging;
use app::App;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
                    "android2rust-iced [--source PATH] [--target TARGET] [--serial SERIAL] [--recipe FILE] [--profile NAME]\n\
                     Launch the cross-platform Iced desktop console for android2rust (Linux, macOS, Windows)."
                );
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

const APP_ICON_RGBA: &[u8] = include_bytes!("../assets/icon_32x32.rgba");

fn main() -> iced::Result {
    let _ = init_logging("warn", None);
    let launch = parse_launch_args_from(std::env::args().skip(1));
    let icon = iced::window::icon::from_rgba(APP_ICON_RGBA.to_vec(), 32, 32).ok();

    iced::application(move || App::new(launch.clone()), App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .window(iced::window::Settings {
            size: iced::Size::new(1360.0, 840.0),
            position: iced::window::Position::Centered,
            icon,
            ..Default::default()
        })
        .run()
}
