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
    acl_cache: &'a AclCache,
) -> Element<'a, Message> {
    let sid_line = obj
        .object_sid()
        .map(|s| format!("sid: {s}"))
        .unwrap_or_default();

    let tabs = Tabs::new(Message::TabSelected)
        .push(
            TAB_ATTRIBUTES,
            TabLabel::Text("Attributes".into()),
            view_attributes(obj),
        )
        .push(
            TAB_ACL,
            TabLabel::Text("ACL".into()),
            view_acl(obj, snap, selected_ace, acl_cache),
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

fn view_attributes(obj: &Object) -> Element<'static, Message> {
    // Sort a snapshot of (name, owned value) pairs and render each row with
    // plain Text widgets (so the rows are 'static and don't tangle with the
    // caller's borrow). ACL rows get selectable text_input; attributes stay
    // non-selectable for now — use the per-ACE Copy button on the ACL tab
    // when you need to copy.
    let mut attrs: Vec<(String, String)> = obj
        .attributes
        .iter()
        .map(|(k, a)| (k.clone(), format_attr_values(&a.values)))
        .collect();
    attrs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut rows: Vec<Element<'static, Message>> = Vec::new();
    for (name, value) in &attrs {
        let name_el: iced::widget::Text<'static, iced::Theme, iced::Renderer> =
            text(name.clone()).width(Length::FillPortion(2));
        let value_el: iced::widget::Text<'static, iced::Theme, iced::Renderer> =
            text(value.clone()).width(Length::FillPortion(5));
        rows.push(row![name_el, value_el].spacing(4).into());
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
) -> Element<'a, Message> {
    let _ = obj; // acl cache already encodes everything we need.
    let _ = snap;
    if let Some(err) = &acl.error {
        return text(err.clone()).into();
    }

    let mut children: Vec<Element<'a, Message>> = Vec::new();
    children.push(text(acl.header.clone()).into());
    children.push(text(format!("owner: {}", acl.owner)).into());
    children.push(text(format!("DACL ({} ACEs):", acl.aces.len())).into());

    for ace in acl.aces.iter() {
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
                        .on_press(Message::CopyToClipboard(row_text))
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

        children.push(card.into());
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
