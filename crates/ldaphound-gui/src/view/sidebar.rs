//! Sidebar — recursive tree view of AD naming contexts.
//!
//! Layout (halloy-style):
//! - Top: filter text_input (with search icon)
//! - Middle: scrollable recursive tree of NC roots
//! - Bottom: "Open .dat" button (like halloy's user menu)
//!
//! Tree rows are flat buttons in a scrollable column; visual hierarchy comes
//! from indentation by tree depth. Recursive DFS over [`Tree`].

use std::collections::HashSet;

use iced::alignment;
use iced::widget::{button, column, container, row, scrollable, space, text, text_input};
use iced::{Element, Length};

use ldaphound_core::{Snapshot, Tree, TreeNode};

use crate::icon;
use crate::message::Message;

const INDENT: f32 = 14.0;
const MAX_DEPTH: usize = 16;

pub fn view<'a>(
    snap: &'a Snapshot,
    tree: &'a Tree,
    expanded: &'a HashSet<String>,
    selected: Option<usize>,
    filter: &'a str,
    parsing: bool,
) -> Element<'a, Message> {
    // Filter input at top.
    let search_box = row![
        icon::search(),
        text_input("Filter...", filter)
            .on_input(Message::FilterChanged)
            .width(Length::Fill),
    ]
    .spacing(6)
    .align_y(alignment::Vertical::Center);

    // Tree body.
    let mut rows: Vec<Element<'a, Message>> = Vec::new();
    for root in &tree.roots {
        walk(root, 0, snap, expanded, selected, filter, &mut rows);
    }
    let tree_col = if rows.is_empty() {
        column![text("(no matches)").color(crate::theme::dim_text())]
            .spacing(1)
    } else {
        column(rows).spacing(1)
    };

    let scroll = scrollable(tree_col).width(Length::Fill);

    // Open .dat button pinned at bottom (halloy's user_menu position).
    let open_btn = button(row![
        icon::folder(),
        text("Open .dat").size(14),
    ]
    .spacing(8)
    .align_y(alignment::Vertical::Center))
    .on_press_maybe(if parsing {
        None
    } else {
        Some(Message::OpenFileClicked)
    })
    .padding(6)
    .width(Length::Fill)
    .style(|t, s| crate::theme::primary(t, s));

    // Compose: search | (scroll tree) | open button.
    let body = column![container(search_box).padding(6), scroll, container(open_btn).padding(6)]
        .spacing(4)
        .height(Length::Fill);

    container(body)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|t| crate::theme::sidebar_background(t))
        .into()
}

fn walk<'a>(
    node: &'a TreeNode,
    depth: usize,
    snap: &'a Snapshot,
    expanded: &'a HashSet<String>,
    selected: Option<usize>,
    filter: &str,
    out: &mut Vec<Element<'a, Message>>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let needle = filter.trim().to_ascii_lowercase();
    let matches_filter = |n: &TreeNode| -> bool {
        if needle.is_empty() {
            return true;
        }
        let o = &snap.objects[n.obj_idx];
        let dn = o.dn().unwrap_or("").to_ascii_lowercase();
        let name = o.display_name().to_ascii_lowercase();
        dn.contains(&needle) || name.contains(&needle)
    };

    if node.is_synthetic() {
        // Only show the synthetic root when it has filter-matching children.
        if node.children.iter().any(matches_filter) || needle.is_empty() {
            out.push(row_label_synthetic(depth, "(lost & found)"));
            for c in &node.children {
                walk(c, depth + 1, snap, expanded, selected, filter, out);
            }
        }
        return;
    }

    if !matches_filter(node) {
        return;
    }

    let obj = &snap.objects[node.obj_idx];
    let dn_lower = obj.dn().unwrap_or("").to_ascii_lowercase();
    let is_container = !node.children.is_empty();
    let is_expanded = expanded.contains(&dn_lower);
    let is_selected = selected == Some(node.obj_idx);

    out.push(row_label(
        depth,
        node.obj_idx,
        obj,
        is_container,
        is_expanded,
        is_selected,
        dn_lower,
    ));

    if is_container && is_expanded {
        for c in &node.children {
            walk(c, depth + 1, snap, expanded, selected, filter, out);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn row_label<'a>(
    depth: usize,
    obj_idx: usize,
    obj: &'a ldaphound_core::Object,
    is_container: bool,
    is_expanded: bool,
    is_selected: bool,
    dn_lower: String,
) -> Element<'a, Message> {
    let chevron: Element<'a, Message> = if is_container {
        let glyph = if is_expanded {
            icon::chevron_down()
        } else {
            icon::chevron_right()
        };
        button(glyph)
            .on_press(Message::ToggleNode(dn_lower))
            .padding(2)
            .style(|t, s| crate::theme::bare(t, s))
            .into()
    } else {
        // Reserve space so leaf rows align with container rows.
        space::Space::new()
            .width(Length::Fixed(icon::ICON_SIZE))
            .into()
    };

    // Icon per object type + leaf RDN label.
    let type_icon = icon::for_object_type(obj.object_type());
    let dn = obj.dn().unwrap_or("?");
    let rdn = dn.split(',').next().unwrap_or(dn).to_string();
    let label_btn = button(
        row![type_icon, text(rdn).size(13)]
            .spacing(6)
            .align_y(alignment::Vertical::Center),
    )
    .on_press(Message::SelectNode(obj_idx))
    .padding([2, 4])
    .width(Length::Fill)
    .style(move |t, s| crate::theme::sidebar_buffer(t, s, is_selected));

    row![
        space::Space::new().width(Length::Fixed(INDENT * depth as f32)),
        chevron,
        label_btn,
    ]
    .align_y(alignment::Vertical::Center)
    .spacing(2)
    .into()
}

fn row_label_synthetic(depth: usize, label: &str) -> Element<'_, Message> {
    row![
        space::Space::new().width(Length::Fixed(INDENT * depth as f32)),
        text(label.to_string()).color(crate::theme::dim_text()),
    ]
    .into()
}

/// Sidebar shown when no snapshot is loaded — still offers the Open button.
pub fn placeholder<'a>(parsing: bool, status: &str) -> Element<'a, Message> {
    let open_btn = button(
        row![icon::folder(), text("Open .dat").size(14)]
            .spacing(8)
            .align_y(alignment::Vertical::Center),
    )
    .on_press_maybe(if parsing {
        None
    } else {
        Some(Message::OpenFileClicked)
    })
    .padding(6)
    .width(Length::Fill)
    .style(|t, s| crate::theme::primary(t, s));

    let body = column![
        container(text(status.to_string()).color(crate::theme::dim_text()))
            .padding(6),
        column![].height(Length::Fill),
        container(open_btn).padding(6),
    ]
    .spacing(4)
    .height(Length::Fill);

    container(body)
        .width(Length::Shrink)
        .height(Length::Fill)
        .style(|t| crate::theme::sidebar_background(t))
        .into()
}
