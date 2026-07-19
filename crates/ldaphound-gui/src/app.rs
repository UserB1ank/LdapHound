//! App state + Elm update loop (function-style, iced 0.14).

use std::collections::HashMap;
use std::path::PathBuf;

use iced::Task;
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length};

use ldaphound_core::{Sid, Snapshot};

use crate::message::Message;
use crate::task;
use crate::view::{ace_panel, object_list};

/// Application state.
pub struct App {
    snapshot: Option<Snapshot>,
    /// SID → object index lookup, built after parse for resolving ACE
    /// trustees to display names.
    sid_index: HashMap<Sid, usize>,

    filter: String,
    /// Indices into `snapshot.objects` that pass the current filter.
    filtered_indices: Vec<usize>,
    selected_object: Option<usize>,

    status: String,
    parsing: bool,
}

/// Construct the initial empty state. iced calls this on startup.
pub fn new() -> App {
    App {
        snapshot: None,
        sid_index: HashMap::new(),
        filter: String::new(),
        filtered_indices: Vec::new(),
        selected_object: None,
        status: "Open a .dat snapshot to begin.".into(),
        parsing: false,
    }
}

/// Compute the window title from current state.
pub fn title(app: &App) -> String {
    match &app.snapshot {
        Some(s) => format!("LdapHound — {}", s.header.server),
        None => "LdapHound".into(),
    }
}

/// The Elm update function: react to a message, return new state + any Task.
pub fn update(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::OpenFileClicked => {
            app.parsing = true;
            app.status = "Selecting file…".into();
            Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .add_filter("ADExplorer snapshot", &["dat"])
                        .pick_file()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Message::FileSelected,
            )
        }
        Message::FileSelected(maybe_path) => match maybe_path {
            Some(path) => {
                app.status = format!("Parsing {}…", path.display());
                app.parsing = true;
                task::parse_snapshot(path)
            }
            None => {
                app.parsing = false;
                Task::none()
            }
        },
        Message::ParseCompleted(result) => {
            app.parsing = false;
            match result {
                Ok(snap) => {
                    app.status = format!(
                        "Loaded {} ({} objects, {} properties)",
                        snap.header.server,
                        snap.objects.len(),
                        snap.properties.len(),
                    );
                    app.snapshot = Some(snap);
                    build_sid_index(app);
                    app.selected_object = None;
                    recompute_filter(app);
                }
                Err(e) => app.status = format!("Parse failed: {e}"), // e is String
            }
            Task::none()
        }
        Message::FilterChanged(s) => {
            app.filter = s;
            recompute_filter(app);
            Task::none()
        }
        Message::ObjectSelected(i) => {
            app.selected_object = Some(i);
            Task::none()
        }
    }
}

/// The view function: render the current state as an iced widget tree.
pub fn view(app: &App) -> Element<'_, Message> {
    let header = row![
        text("LdapHound").size(20),
        button("Open .dat").on_press_maybe(if app.parsing {
            None
        } else {
            Some(Message::OpenFileClicked)
        }),
        text(&app.status),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let body: Element<Message> = match &app.snapshot {
        Some(snap) => {
            let left = object_list::view(snap, &app.filter, &app.filtered_indices, app.selected_object);
            let right = match app.selected_object.and_then(|i| snap.objects.get(i)) {
                Some(o) => ace_panel::view(o, snap, &app.sid_index),
                None => container(text("Select an object.")).center(Length::Fill).into(),
            };
            row![left, right].spacing(8).height(Length::Fill).into()
        }
        None => container(text("No snapshot loaded."))
            .center(Length::Fill)
            .height(Length::Fill)
            .into(),
    };

    let content = column![header, body].spacing(8);
    container(scrollable(content))
        .padding(12)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn recompute_filter(app: &mut App) {
    app.filtered_indices.clear();
    if let Some(snap) = &app.snapshot {
        let f = app.filter.trim().to_ascii_lowercase();
        for (i, o) in snap.objects.iter().enumerate() {
            if f.is_empty() {
                app.filtered_indices.push(i);
                continue;
            }
            let dn = o.dn().unwrap_or("").to_ascii_lowercase();
            let name = o.display_name().to_ascii_lowercase();
            if dn.contains(&f) || name.contains(&f) {
                app.filtered_indices.push(i);
            }
        }
    }
}

fn build_sid_index(app: &mut App) {
    app.sid_index.clear();
    if let Some(snap) = &app.snapshot {
        for (i, o) in snap.objects.iter().enumerate() {
            if let Some(sid) = o.object_sid() {
                app.sid_index.insert(sid, i);
            }
        }
    }
}

// Suppress unused warning for PathBuf re-export if any. Kept for clarity
// for downstream tasks that accept paths.
#[allow(dead_code)]
fn _path_type_hint(_: PathBuf) {}
