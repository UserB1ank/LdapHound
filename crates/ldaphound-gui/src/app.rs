//! App state + Elm update loop (function-style, iced 0.14).
//!
//! Layout: top header bar, then a `pane_grid` with two panes separated by a
//! draggable divider — left = AD tree sidebar, right = selected object's
//! details (Attributes / ACL tabs).

use std::collections::HashSet;

use iced::Task;
use iced::widget::pane_grid::{self, PaneGrid};
use iced::widget::{button, column, container, row, text};
use iced::{Alignment, Element, Length};

use ldaphound_core::{Snapshot, Tree};

use crate::message::Message;
use crate::task;
use crate::view::{object_view, sidebar};

/// Right-pane kind so PaneGrid can dispatch view per pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Sidebar,
    Main,
}

/// Application state.
pub struct App {
    snapshot: Option<Snapshot>,
    tree: Option<Tree>,

    /// Two-pane layout: [Sidebar | Main] with a draggable divider.
    panes: pane_grid::State<Pane>,

    /// DNs (lowercased) of currently-expanded tree nodes.
    expanded: HashSet<String>,
    /// Selected object index, shown in the right pane.
    selected: Option<usize>,
    /// Selected ACE index within the current object's DACL.
    selected_ace: Option<usize>,
    /// Right pane active tab: 0 = Attributes, 1 = ACL.
    active_tab: usize,

    status: String,
    parsing: bool,
}

pub fn new() -> App {
    // Start with a single Sidebar pane; split it to the right to create the
    // Main pane. The split returns the new pane's id, which we don't need
    // to track explicitly since view() dispatches on Pane variant.
    let (mut panes, _first) = pane_grid::State::new(Pane::Sidebar);
    let _ = panes.split(pane_grid::Axis::Vertical, panes.panes.keys().next().copied().unwrap(), Pane::Main);

    App {
        snapshot: None,
        tree: None,
        panes,
        expanded: HashSet::new(),
        selected: None,
        selected_ace: None,
        active_tab: 0,
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
                    app.selected_ace = None;
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
            app.selected_ace = None;
            Task::none()
        }
        Message::SelectAce(i) => {
            app.selected_ace = if app.selected_ace == Some(i) {
                None
            } else {
                Some(i)
            };
            Task::none()
        }
        Message::CopyToClipboard(s) => {
            app.status = format!("Copied {} chars to clipboard", s.len());
            iced::clipboard::write(s)
        }
        Message::TabSelected(tab) => {
            app.active_tab = tab;
            Task::none()
        }
        Message::PaneResized(pane_grid::ResizeEvent { split, ratio }) => {
            app.panes.resize(split, ratio);
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
            // Capture only shared refs so the Fn closure can re-build per
            // pane on each layout pass without moving owned Elements.
            let expanded = &app.expanded;
            let selected = app.selected;
            let selected_ace = app.selected_ace;
            let active_tab = app.active_tab;

            PaneGrid::new(&app.panes, move |_id, pane, _maximized| {
                let element: iced::Element<'_, Message> = match pane {
                    Pane::Sidebar => sidebar::view(snap, tree, expanded, selected),
                    Pane::Main => match selected.and_then(|i| snap.objects.get(i)) {
                        Some(o) => object_view::view(o, snap, selected_ace, active_tab),
                        None => container(text("Select an object in the tree."))
                            .center(Length::Fill)
                            .into(),
                    },
                };
                pane_grid::Content::new(element)
            })
            .spacing(4) // divider thickness (draggable area)
            .on_resize(8, Message::PaneResized)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
        }
        _ => container(text("No snapshot loaded."))
            .center(Length::Fill)
            .height(Length::Fill)
            .into(),
    };

    let content = column![header, body].spacing(8).height(Length::Fill);
    container(content)
        .padding(4)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}
