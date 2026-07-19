//! ldaphound-gui — iced 0.14 GUI for browsing ACL relationships.
//!
//! Uses iced's function-based API (`iced::application(new, update, view)`)
//! instead of the `Application` trait. Parsing runs on a background thread
//! via `Task::perform` so the UI stays responsive on large snapshots.
//! See `docs/snapshot-format.md` §11.

// Hide the console window in release builds; keep it visible in debug so
// panic backtraces and eprintln! show up during development.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
#[allow(dead_code)]
mod icon;
mod message;
mod task;
mod theme;
mod view;

fn main() -> iced::Result {
    iced::application(app::new, app::update, app::view)
        .title(app::title)
        .theme(theme)
        // Load the bundled Bootstrap Icons TTF so `icon::ICON_FONT` resolves.
        .font(include_bytes!("../assets/bootstrap-icons.ttf").as_slice())
        .run()
}

/// Static theme function — avoids HRTB inference issues with closures.
fn theme(_app: &app::App) -> iced::Theme {
    iced::Theme::Dark
}
