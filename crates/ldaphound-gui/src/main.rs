//! ldaphound-gui — iced 0.14 GUI for browsing ACL relationships.
//!
//! Uses iced's function-based API (`iced::application(new, update, view)`)
//! instead of the `Application` trait — the recommended style in 0.14.
//!
//! Parsing runs on a background thread via `Task::perform` so the UI stays
//! responsive on large snapshots. See `docs/snapshot-format.md` §11.

// Hide the console window on Windows in release builds. Kept visible in
// debug so panic backtraces and eprintln! show up during development.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod message;
mod task;
mod theme;
mod view;

fn main() -> iced::Result {
    iced::application(app::new, app::update, app::view)
        .title(app::title)
        .theme(theme)
        .run()
}

/// Static theme function — avoids HRTB inference issues with closures.
fn theme(_app: &app::App) -> iced::Theme {
    iced::Theme::Dark
}
