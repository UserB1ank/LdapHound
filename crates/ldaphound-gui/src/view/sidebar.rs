//! Sidebar — recursive tree view of AD naming contexts.
//!
//! Modeled on halloy's sidebar: a flat `Scrollable<Column>` of buttons whose
//! visual hierarchy comes from indentation by tree depth. Recursive DFS
//! over [`Tree`] — children only rendered when their parent is in the
//! `expanded` set.

use std::collections::HashSet;

use iced::alignment;
use iced::widget::{button, column, container, row, scrollable, space, text};
use iced::{Element, Length};

use ldaphound_core::{Snapshot, Tree, TreeNode};

use crate::message::Message;

const INDENT: f32 = 16.0;
const MAX_DEPTH: usize = 16;

pub fn view<'a>(
    snap: &'a Snapshot,
    tree: &'a Tree,
    expanded: &'a HashSet<String>,
    selected: Option<usize>,
) -> Element<'a, Message> {
    let mut rows: Vec<Element<'a, Message>> = Vec::new();
    for root in &tree.roots {
        walk(root, 0, snap, expanded, selected, &mut rows);
    }

    let body = column(rows).spacing(1);
    let scroll = scrollable(body);
    container(scroll)
        .width(Length::FillPortion(2))
        .height(Length::Fill)
        .padding(4)
        .into()
}

fn walk<'a>(
    node: &'a TreeNode,
    depth: usize,
    snap: &'a Snapshot,
    expanded: &'a HashSet<String>,
    selected: Option<usize>,
    out: &mut Vec<Element<'a, Message>>,
) {
    if depth > MAX_DEPTH {
        return;
    }

    // Synthetic "Lost & Found" root.
    if node.is_synthetic() {
        out.push(row_label_synthetic(depth, "(lost & found)"));
        if !node.children.is_empty() {
            for c in &node.children {
                walk(c, depth + 1, snap, expanded, selected, out);
            }
        }
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
        dn_lower.clone(),
    ));

    if is_container && is_expanded {
        for c in &node.children {
            walk(c, depth + 1, snap, expanded, selected, out);
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
    let chevron = if is_container {
        text(if is_expanded { "▾" } else { "▸" }).size(12)
    } else {
        text(" ").size(12)
    };

    let chevron_btn: Element<'a, Message> = if is_container {
        button(chevron)
            .on_press(Message::ToggleNode(dn_lower))
            .padding(2)
            .into()
    } else {
        chevron.into()
    };

    // Leaf RDN (first component of DN) keeps the tree readable. Prefix with
    // "▶ " when selected since iced 0.14 has no theme::Button style enum.
    let dn = obj.dn().unwrap_or("?");
    let rdn = dn.split(',').next().unwrap_or(dn).to_string();
    let label_str = if is_selected {
        format!("▶ {rdn}")
    } else {
        rdn
    };
    let label_btn: Element<'a, Message> = button(text(label_str))
        .on_press(Message::SelectNode(obj_idx))
        .padding(2)
        .into();

    row![
        space::Space::new().width(Length::Fixed(INDENT * depth as f32)),
        chevron_btn,
        label_btn,
    ]
    .align_y(alignment::Vertical::Center)
    .spacing(2)
    .into()
}

fn row_label_synthetic(depth: usize, label: &str) -> Element<'_, Message> {
    row![
        space::Space::new().width(Length::Fixed(INDENT * depth as f32)),
        text(label.to_string()),
    ]
    .into()
}
