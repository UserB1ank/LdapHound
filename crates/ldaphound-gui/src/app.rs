//! App state + Elm update loop (function-style, iced 0.14).
//!
//! Layout (halloy-inspired): `row![sidebar, main]`.
//! - Sidebar: scrollable recursive tree of AD naming contexts.
//! - Main: selected object's header + attributes + ACL breakdown.

use std::collections::HashSet;

use iced::Task;
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length};

use ldaphound_core::{Snapshot, Tree};

use crate::message::Message;
use crate::task;
use crate::view::{object_view, sidebar};

/// Application state.
pub struct App {
    snapshot: Option<Snapshot>,
    tree: Option<Tree>,

    /// DNs (lowercased) of currently-expanded tree nodes. Defaults to the
    /// three NC roots when a snapshot loads.
    expanded: HashSet<String>,
    /// Selected object index, shown in the right pane.
    selected: Option<usize>,

    status: String,
    parsing: bool,
}

pub fn new() -> App {
    App {
        snapshot: None,
        tree: None,
        expanded: HashSet::new(),
        selected: None,
        status: "Open a .dat snapshot to begin.".into(),
        parsing: false,
    }
}

pub fn title(app: &App) -> String {
    match &app.snapshot {
        Some(s) => format!("LdapHound — {}", s.header.server),
        None => "LdapHound".into(),
    }
}

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
                    // Build tree, expand the 3 NC roots by default.
                    let tree = snap.build_tree();
                    let mut expanded = HashSet::new();
                    for root in &tree.roots {
                        if !root.is_synthetic() {
                            if let Some(dn) = snap.objects[root.obj_idx].dn() {
                                expanded.insert(dn.to_ascii_lowercase());
                            }
                        }
                    }
                    app.tree = Some(tree);
                    app.expanded = expanded;
                    app.selected = None;
                    app.snapshot = Some(snap);
                }
                Err(e) => app.status = format!("Parse failed: {e}"),
            }
            Task::none()
        }
        Message::ToggleNode(dn) => {
            if app.expanded.contains(&dn) {
                app.expanded.remove(&dn);
            } else {
                app.expanded.insert(dn);
            }
            Task::none()
        }
        Message::SelectNode(i) => {
            app.selected = Some(i);
            Task::none()
        }
    }
}

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

    let body: Element<'_, Message> = match (&app.snapshot, &app.tree) {
        (Some(snap), Some(tree)) => {
            let left = sidebar::view(snap, tree, &app.expanded, app.selected);
            let right = match app.selected.and_then(|i| snap.objects.get(i)) {
                Some(o) => object_view::view(o, snap),
                None => container(text("Select an object in the tree."))
                    .center(Length::Fill)
                    .into(),
            };
            row![left, right].spacing(4).height(Length::Fill).into()
        }
        _ => container(text("No snapshot loaded."))
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
