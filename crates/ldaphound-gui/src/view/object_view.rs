//! Right pane — selected object's details.
//!
//! Layout: fixed header (display name + DN + SID), then an `iced_aw::Tabs`
//! switching between Attributes (sorted name|value list) and ACL (owner,
//! flags, and a column-aligned ACE grid with selectable rows).

use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Length};
use iced_aw::{TabLabel, Tabs};

use ldaphound_core::security::descriptor::SecurityDescriptor;
use ldaphound_core::{Object, Snapshot};

use crate::message::Message;

// Tab indices — kept in sync with the order tabs are pushed below.
const TAB_ATTRIBUTES: usize = 0;
const TAB_ACL: usize = 1;

pub fn view<'a>(
    obj: &'a Object,
    snap: &'a Snapshot,
    selected_ace: Option<usize>,
    active_tab: usize,
    attr_cache: &'a AttrCache,
    acl_cache: &'a AclCache,
    acl_filter_trustee: Option<&'a str>,
    acl_filter_right: Option<&'a str>,
) -> Element<'a, Message> {
    let sid_line = obj
        .object_sid()
        .map(|s| format!("sid: {s}"))
        .unwrap_or_default();

    let tabs = Tabs::new(Message::TabSelected)
        .push(
            TAB_ATTRIBUTES,
            TabLabel::Text("Attributes".into()),
            view_attributes(attr_cache),
        )
        .push(
            TAB_ACL,
            TabLabel::Text("ACL".into()),
            view_acl(
                obj,
                snap,
                selected_ace,
                acl_cache,
                acl_filter_trustee,
                acl_filter_right,
            ),
        )
        .set_active_tab(&active_tab)
        .height(Length::Fill);

    let mut col_children: Vec<Element<'a, Message>> = Vec::new();
    if !sid_line.is_empty() {
        col_children.push(
            text(sid_line)
                .color(crate::theme::dim_text())
                .into(),
        );
    }
    col_children.push(tabs.into());
    let col = column(col_children).spacing(4);
    container(scrollable(col))
        .width(Length::Fill)
        .height(Length::Fill)
        .padding([4, 10])
        .style(|t| crate::theme::pane_body(t))
        .into()
}

fn view_attributes<'a>(attr_cache: &'a AttrCache) -> Element<'a, Message> {
    let mut rows: Vec<Element<'a, Message>> = Vec::new();
    for (name, value) in attr_cache.pairs.iter() {
        rows.push(name_value_row(name, value));
    }
    if rows.is_empty() {
        rows.push(text("(no attributes)").into());
    }
    column(rows).spacing(2).into()
}

fn view_acl<'a>(
    obj: &'a Object,
    snap: &'a Snapshot,
    selected_ace: Option<usize>,
    acl: &'a AclCache,
    filter_trustee: Option<&'a str>,
    filter_right: Option<&'a str>,
) -> Element<'a, Message> {
    let _ = obj; // acl cache already encodes everything we need.
    let _ = snap;
    if let Some(err) = &acl.error {
        return text(err.clone()).into();
    }

    // Count by trustee + right for the categorisation bar.
    use std::collections::BTreeMap;
    let mut by_trustee: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_right: BTreeMap<&str, usize> = BTreeMap::new();
    for ace in acl.aces.iter() {
        *by_trustee.entry(ace.trustee.as_str()).or_insert(0) += 1;
        *by_right.entry(ace.right.as_str()).or_insert(0) += 1;
    }

    let mut children: Vec<Element<'a, Message>> = Vec::new();
    children.push(text(acl.header.clone()).into());
    children.push(text(format!("owner: {}", acl.owner)).into());

    // Single-row filter bar with two dropdowns (Trustee + Right). Options
    // carry their count as a suffix so users see distribution at a glance;
    // the underlying value is the bare name so filter comparison is simple.
    use iced::widget::pick_list;
    // Option list includes a leading "(all)" entry so users can clear the
    // filter from the dropdown itself.
    let mut trustee_options: Vec<String> = vec!["(all)".to_string()];
    trustee_options.extend(
        by_trustee
            .iter()
            .map(|(name, count)| format!("{name} ({count})")),
    );
    let trustee_selected = filter_trustee.map(|t| {
        let count = by_trustee.get(t).copied().unwrap_or(0);
        format!("{t} ({count})")
    });
    let trustee_list = pick_list(
        trustee_options,
        trustee_selected,
        |pick: String| {
            if pick == "(all)" {
                Message::ToggleAclTrusteeFilter(String::new())
            } else {
                let name = pick.split(" (").next().unwrap_or(&pick).to_string();
                Message::ToggleAclTrusteeFilter(name)
            }
        },
    )
    .placeholder("All trustees");

    let mut right_options: Vec<String> = vec!["(all)".to_string()];
    right_options.extend(
        by_right
            .iter()
            .map(|(name, count)| format!("{name} ({count})")),
    );
    let right_selected = filter_right.map(|r| {
        let count = by_right.get(r).copied().unwrap_or(0);
        format!("{r} ({count})")
    });
    let right_list = pick_list(
        right_options,
        right_selected,
        |pick: String| {
            if pick == "(all)" {
                Message::ToggleAclRightFilter(String::new())
            } else {
                let name = pick.split(" (").next().unwrap_or(&pick).to_string();
                Message::ToggleAclRightFilter(name)
            }
        },
    )
    .placeholder("All rights");

    children.push(
        iced::widget::row![
            text("Trustee:").size(13),
            trustee_list,
            text("Right:").size(13),
            right_list,
        ]
        .spacing(8)
        .align_y(iced::alignment::Vertical::Center)
        .padding([4, 0])
        .into(),
    );

    // Apply filters + render matching ACEs.
    let visible: Vec<&AceLine> = acl
        .aces
        .iter()
        .filter(|ace| {
            if let Some(t) = filter_trustee {
                if ace.trustee.as_str() != t {
                    return false;
                }
            }
            if let Some(r) = filter_right {
                if ace.right.as_str() != r {
                    return false;
                }
            }
            true
        })
        .collect();
    children.push(
        text(format!("DACL ({} of {} ACEs):", visible.len(), acl.aces.len()))
            .into(),
    );

    for ace in visible.iter() {
        let i = ace.idx;
        let is_sel = selected_ace == Some(i);
        let row_text = format_ace_row(i, ace);

        let mut field_rows: Vec<Element<'a, Message>> = Vec::new();
        field_rows.push(name_value_row("#", &ace.idx_str));
        field_rows.push(name_value_row("Kind", &ace.kind));
        field_rows.push(name_value_row("Right", &ace.right));
        field_rows.push(name_value_row("Mask", &ace.mask));
        field_rows.push(name_value_row("Inherited", &ace.inherited_str));
        field_rows.push(name_value_row("Trustee", &ace.trustee));

        if is_sel {
            field_rows.push(
                row![
                    iced::widget::Space::new().width(Length::Fill),
                    button(text("Copy").size(12))
                        .on_press(Message::CopyToClipboard(row_text.clone()))
                        .padding([2, 6])
                        .style(|t, s| crate::theme::secondary(t, s)),
                ]
                .into(),
            );
        }

        let card_body = column(field_rows).spacing(2);
        let card = button(card_body)
            .on_press(Message::SelectAce(i))
            .padding(6)
            .width(Length::Fill)
            .style(move |t, s| crate::theme::sidebar_buffer(t, s, is_sel));

        // Right-click menu: Copy ACE always; Go to trustee when the ACE
        // carries a SID. ContextMenu's overlay closure is Fn (called on
        // every right-click), so we capture Clone-able inputs and rebuild
        // the widget tree each invocation — Element itself isn't Clone.
        let row_text_for_copy = row_text.clone();
        let trustee_sid_for_goto = ace.trustee_sid.clone();
        let card_with_menu = iced_aw::ContextMenu::new(card, move || {
            let mut items: Vec<Element<'static, Message>> = Vec::new();
            items.push(
                button(text("Copy ACE").size(12))
                    .on_press(Message::CopyToClipboard(row_text_for_copy.clone()))
                    .padding([4, 8])
                    .style(|t, s| crate::theme::bare(t, s))
                    .into(),
            );
            if let Some(sid) = trustee_sid_for_goto.clone() {
                items.push(
                    button(text(format!("Go to trustee ({sid})")).size(12))
                        .on_press(Message::SelectBySid(sid))
                        .padding([4, 8])
                        .style(|t, s| crate::theme::bare(t, s))
                        .into(),
                );
            }
            column(items).width(Length::Shrink).into()
        });

        children.push(card_with_menu.into());
    }
    column(children).spacing(4).into()
}

/// One `name: value` row. Value uses a read-only `text_input` so the user
/// can drag-select substrings and Ctrl+C them. `value` is borrowed for the
/// returned element's lifetime — the caller must keep it alive (e.g. in an
/// `AclCache` stored on App state, or a sorted attribute vec).
fn name_value_row<'a>(name: &'a str, value: &'a str) -> Element<'a, Message> {
    use iced::widget::text_input;
    let name_el: iced::widget::Text<'a, iced::Theme, iced::Renderer> =
        text(name.to_string()).width(Length::FillPortion(2));
    let value_el: iced::widget::TextInput<'a, Message, iced::Theme, iced::Renderer> =
        text_input("", value).width(Length::FillPortion(5));
    row![name_el, value_el].spacing(4).into()
}

fn format_attr_values(values: &[ldaphound_core::snapshot::AttributeValue]) -> String {
    if values.len() == 1 {
        format!("{}", values[0])
    } else {
        let parts: Vec<String> = values.iter().map(|v| format!("{v}")).collect();
        format!("[{}]", parts.join(", "))
    }
}

fn format_ace_row(i: usize, ace: &AceLine) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        i,
        ace.kind,
        ace.right,
        ace.mask,
        if ace.inherited { "inherited" } else { "explicit" },
        ace.trustee,
    )
}

// Owned ACL display data, decoupled from the borrowed SD parse result.
/// Cached on the App so the view can borrow it across renders (needed for
/// selectable text_input widgets, which borrow their `&str` value for the
/// element's lifetime).
pub struct AclCache {
    pub header: String,
    pub owner: String,
    pub aces: Vec<AceLine>,
    pub error: Option<String>,
}

impl Default for AclCache {
    fn default() -> Self {
        Self {
            header: String::new(),
            owner: String::new(),
            aces: Vec::new(),
            error: None,
        }
    }
}

/// Cached, sorted (name, value) pairs for the Attributes tab. Borrowed by
/// `view_attributes` so the rows can hand `&str` to read-only `text_input`
/// widgets (selectable text). Stored on the App next to AclCache.
pub struct AttrCache {
    pub pairs: Vec<(String, String)>,
}

impl Default for AttrCache {
    fn default() -> Self {
        Self { pairs: Vec::new() }
    }
}

/// Build the attribute display data once per object selection.
pub fn build_attr_cache(obj: &Object) -> AttrCache {
    let mut pairs: Vec<(String, String)> = obj
        .attributes
        .iter()
        .map(|(k, a)| (k.clone(), format_attr_values(&a.values)))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    AttrCache { pairs }
}

pub struct AceLine {
    pub idx: usize,
    pub idx_str: String,
    pub kind: String,
    pub right: String,
    pub mask: String,
    pub inherited: bool,
    /// Pre-formatted "inherited" / "explicit".
    pub inherited_str: String,
    pub trustee: String,
    /// Parsed SID for the trustee, if any. Drives the "Go to trustee" right-
    /// click action.
    pub trustee_sid: Option<ldaphound_core::Sid>,
}

/// Build ACL display data once per object selection. Stored on the App so
/// view_acl can borrow from it on every render.
pub fn build_acl_cache(obj: &Object, snap: &Snapshot) -> AclCache {
    let Some(bytes) = obj.ntsd_bytes() else {
        return AclCache {
            header: String::new(),
            owner: String::new(),
            aces: Vec::new(),
            error: Some("(no nTSecurityDescriptor)".into()),
        };
    };
    match SecurityDescriptor::from_bytes(bytes) {
        Ok(sd) => {
            let header = format!(
                "SD: {} bytes, flags=0x{:04X}, DACL protected={}",
                bytes.len(),
                sd.control_flags,
                sd.is_dacl_protected(),
            );
            let owner = sd
                .owner
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into());
            let aces: Vec<AceLine> = sd
                .dacl
                .iter()
                .flat_map(|d| d.aces.iter())
                .enumerate()
                .map(|(idx, ace)| {
                    use ldaphound_core::security::AceType;
                    let kind = match ace.ace_type() {
                        AceType::AccessAllowed => "Allow",
                        AceType::AccessDenied => "Deny",
                        AceType::AccessAllowedObject => "AllowObj",
                        AceType::AccessDeniedObject => "DenyObj",
                        _ => "Other",
                    }
                    .to_string();
                    let right = ace.right_name().unwrap_or_else(|| "-".into());
                    let mask = ace
                        .mask()
                        .map(|m| format!("{m} [{}]", m.human_names().join(",")))
                        .unwrap_or_else(|| "-".into());
                    let inherited = ace.is_inherited();
                    let inherited_str = if inherited { "inherited".into() } else { "explicit".into() };
                    let trustee_sid = ace.trustee().cloned();
                    let trustee = match ace.trustee() {
                        Some(sid) => match find_by_sid(snap, sid) {
                            Some(o) => {
                                let principal = o.principal_name();
                                let class_owned = o.object_classes();
                                let class = class_owned
                                    .last()
                                    .map(|s| s.as_str())
                                    .unwrap_or("?");
                                format!("{principal}  [{class}]  {sid}")
                            }
                            None => format!("{sid}  (unresolved)"),
                        },
                        None => "-".into(),
                    };
                    AceLine {
                        idx,
                        idx_str: idx.to_string(),
                        kind,
                        right,
                        mask,
                        inherited,
                        inherited_str,
                        trustee,
                        trustee_sid,
                    }
                })
                .collect();
            AclCache {
                header,
                owner,
                aces,
                error: None,
            }
        }
        Err(e) => AclCache {
            header: String::new(),
            owner: String::new(),
            aces: Vec::new(),
            error: Some(format!("SD parse error: {e}")),
        },
    }
}

fn find_by_sid<'a>(snap: &'a Snapshot, sid: &ldaphound_core::Sid) -> Option<&'a Object> {
    snap.objects
        .iter()
        .find(|o| o.object_sid().map(|s| &s == sid).unwrap_or(false))
}
