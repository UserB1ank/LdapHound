//! App state + Elm update loop (function-style, iced 0.14).
//!
//! Layout (halloy-inspired):
//! ```text
//! Row![
//!     sidebar,                                // 顶部 filter，中间 tree，底部 Open
//!     container(PaneGrid).padding(8),         // 主内容，每 pane 含 TitleBar
//! ]
//! ```

use std::collections::HashSet;

use iced::Task;
use iced::widget::pane_grid::{self, PaneGrid};
use iced::widget::{column, container, row, text};
use iced::{Element, Length};

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
    /// Sidebar filter text (substring on DN / display name).
    filter: String,

    status: String,
    parsing: bool,
}

pub fn new() -> App {
    let (mut panes, _first) = pane_grid::State::new(Pane::Sidebar);
    let _ = panes.split(
        pane_grid::Axis::Vertical,
        panes.panes.keys().next().copied().unwrap(),
        Pane::Main,
    );

    App {
        snapshot: None,
        tree: None,
        panes,
        expanded: HashSet::new(),
        selected: None,
        selected_ace: None,
        active_tab: 0,
        filter: String::new(),
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
                        "{} objects loaded from {}",
                        snap.objects.len(),
                        snap.header.server,
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
                    app.filter.clear();
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
            app.status = format!("Copied {} chars", s.len());
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
        Message::FilterChanged(s) => {
            app.filter = s;
            Task::none()
        }
    }
}

pub fn view(app: &App) -> Element<'_, Message> {
    let body: Element<'_, Message> = match (&app.snapshot, &app.tree) {
        (Some(snap), Some(tree)) => {
            let sidebar_el = sidebar::view(
                snap,
                tree,
                &app.expanded,
                app.selected,
                &app.filter,
                app.parsing,
            );

            let expanded = &app.expanded;
            let selected = app.selected;
            let selected_ace = app.selected_ace;
            let active_tab = app.active_tab;

            // PaneGrid holds only the Main pane; the Sidebar lives outside
            // it (halloy puts the sidebar in the wrapping Row and PaneGrid
            // holds the buffer panes). That keeps the sidebar width fixed
            // while only the main content is user-resizable internally.
            let pane_grid: Element<'_, Message> = PaneGrid::new(&app.panes, move |_id, pane, _m| {
                let element: iced::Element<'_, Message> = match pane {
                    Pane::Sidebar => sidebar::view(
                        snap,
                        tree,
                        expanded,
                        selected,
                        &app.filter,
                        app.parsing,
                    ),
                    Pane::Main => main_pane(selected, selected_ace, active_tab, snap),
                };
                pane_grid::Content::new(element)
            })
            .spacing(4)
            .on_resize(8, Message::PaneResized)
            .width(Length::Fill)
            .height(Length::Fill)
            .into();

            row![sidebar_el, container(pane_grid).padding(8)]
                .spacing(0)
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        }
        _ => sidebar::placeholder(app.parsing, &app.status),
    };

    container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Render the Main pane: a title bar with the object's display name + class,
/// then the body (Attributes / ACL tabs).
fn main_pane(
    selected: Option<usize>,
    selected_ace: Option<usize>,
    active_tab: usize,
    snap: &Snapshot,
) -> Element<'_, Message> {
    let Some(idx) = selected else {
        return container(text("Select an object in the tree."))
            .center(Length::Fill)
            .width(Length::Fill)
            .height(Length::Fill)
            .into();
    };
    let Some(obj) = snap.objects.get(idx) else {
        return text("(object not found)").into();
    };

    // Title bar: display name + class badge + DN subtitle.
    let title_text = obj.display_name();
    let class = obj
        .object_classes()
        .last()
        .map(|s| s.as_str())
        .unwrap_or("?")
        .to_string();
    let dn = obj.dn().unwrap_or("").to_string();
    let title_bar = container(
        column![
            row![
                crate::icon::for_object_type(obj.object_type()),
                text(title_text).size(15),
                text(class).color(crate::theme::dim_text()),
            ]
            .spacing(8)
            .align_y(iced::alignment::Vertical::Center),
            text(dn).color(crate::theme::dim_text()),
        ]
        .spacing(2),
    )
    .padding([6, 10])
    .width(Length::Fill)
    .style(|t| crate::theme::pane_title_bar(t));

    let body = object_view::view(obj, snap, selected_ace, active_tab);

    column![title_bar, body]
        .width(Length::Fill)
        .height(Length::Fill)
        .spacing(0)
        .into()
}
