//! Right pane — selected object's details.
//!
//! Layout: fixed header (display name + DN + SID), then an `iced_aw::Tabs`
//! switching between Attributes (sorted name|value list) and ACL (owner,
//! flags, and a column-aligned ACE grid with selectable rows).

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length};
use iced_aw::{TabLabel, Tabs};

use ldaphound_core::security::descriptor::SecurityDescriptor;
use ldaphound_core::{Object, Snapshot};

use crate::message::Message;

// Tab indices — kept in sync with the order tabs are pushed below.
const TAB_ATTRIBUTES: usize = 0;
const TAB_ACL: usize = 1;

// Fixed column widths (portion units) for the ACE grid.
const COL_IDX: u16 = 1;
const COL_KIND: u16 = 4;
const COL_RIGHT: u16 = 14;
const COL_MASK: u16 = 10;
const COL_INHERITED: u16 = 5;
const COL_TRUSTEE: u16 = 22;

pub fn view<'a>(
    obj: &'a Object,
    snap: &'a Snapshot,
    selected_ace: Option<usize>,
    active_tab: usize,
) -> Element<'a, Message> {
    // Header lives in the pane TitleBar (built by app::main_pane); here we
    // only render the SID line + tabbed content.
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
            view_acl(obj, snap, selected_ace),
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

fn view_attributes(obj: &Object) -> Element<'_, Message> {
    let mut attrs: Vec<(&String, String)> = obj
        .attributes
        .iter()
        .map(|(k, a)| (k, format_attr_values(&a.values)))
        .collect();
    attrs.sort_by(|a, b| a.0.cmp(b.0));

    let mut rows: Vec<Element<'_, Message>> = Vec::new();
    for (name, joined) in attrs {
        // Read-only text_input makes the value selectable + Ctrl+C-able.
        // No on_input closure means edits are silently dropped (the field
        // still re-renders from `joined` on each frame).
        let name_el: iced::widget::Text<'_, iced::Theme, iced::Renderer> =
            text(format!("{name}:")).width(Length::FillPortion(2));
        let value_el: iced::widget::TextInput<'_, Message, iced::Theme, iced::Renderer> =
            text_input("", &joined).width(Length::FillPortion(5));
        rows.push(
            row![name_el, value_el]
                .spacing(4)
                .into(),
        );
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
) -> Element<'a, Message> {
    let acl = match obj.ntsd_bytes() {
        Some(b) => AclView::from_bytes(b, snap),
        None => AclView::Absent,
    };

    let mut children: Vec<Element<'a, Message>> = Vec::new();
    match acl {
        AclView::Absent => children.push(text("(no nTSecurityDescriptor)").into()),
        AclView::Err(e) => children.push(text(format!("SD parse error: {e}")).into()),
        AclView::Ok {
            header,
            owner,
            aces,
        } => {
            children.push(text(header).into());
            children.push(text(format!("owner: {owner}")).into());
            children.push(text(format!("DACL ({} ACEs):", aces.len())).into());

            // Header row of the grid.
            children.push(
                row![
                    cell_text("#", COL_IDX),
                    cell_text("Kind", COL_KIND),
                    cell_text("Right", COL_RIGHT),
                    cell_text("Mask", COL_MASK),
                    cell_text("Inherited", COL_INHERITED),
                    cell_text("Trustee", COL_TRUSTEE),
                ]
                .spacing(4)
                .into(),
            );

            // Body rows. Selection is shown by background colour (no glyph).
            for (i, ace) in aces.iter().enumerate() {
                let is_sel = selected_ace == Some(i);
                let row_text = format_ace_row(i, ace);

                let row_btn = button(
                    row![
                        cell_text(i, COL_IDX),
                        cell_text(&ace.kind, COL_KIND),
                        cell_text(&ace.right, COL_RIGHT),
                        cell_text(&ace.mask, COL_MASK),
                        cell_text(
                            if ace.inherited { "inherited" } else { "explicit" },
                            COL_INHERITED
                        ),
                        cell_text(&ace.trustee, COL_TRUSTEE),
                    ]
                    .spacing(4),
                )
                .on_press(Message::SelectAce(i))
                .padding(2)
                .style(move |t, s| crate::theme::sidebar_buffer(t, s, is_sel));

                let row_el: Element<'a, Message> = if is_sel {
                    row![
                        row_btn,
                        button(text("Copy"))
                            .on_press(Message::CopyToClipboard(row_text))
                            .padding(2)
                            .style(|t, s| crate::theme::secondary(t, s)),
                    ]
                    .spacing(4)
                    .into()
                } else {
                    row_btn.into()
                };
                children.push(row_el);
            }
        }
    }
    column(children).spacing(4).into()
}

fn cell_text(s: impl ToString, portion: u16) -> Element<'static, Message> {
    text(s.to_string())
        .width(Length::FillPortion(portion))
        .into()
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
enum AclView {
    Absent,
    Err(String),
    Ok {
        header: String,
        owner: String,
        aces: Vec<AceLine>,
    },
}

struct AceLine {
    kind: String,
    right: String,
    mask: String,
    inherited: bool,
    trustee: String,
}

impl AclView {
    fn from_bytes(bytes: &[u8], snap: &Snapshot) -> Self {
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
                    .map(|ace| {
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
                        let trustee = match ace.trustee() {
                            Some(sid) => match find_by_sid(snap, sid) {
                                Some(o) => format!(
                                    "{sid} = {} ({})",
                                    o.display_name(),
                                    o.object_classes().last().map(|s| s.as_str()).unwrap_or("?")
                                ),
                                None => format!("{sid} (unresolved)"),
                            },
                            None => "-".into(),
                        };
                        AceLine {
                            kind,
                            right,
                            mask,
                            inherited,
                            trustee,
                        }
                    })
                    .collect();
                AclView::Ok {
                    header,
                    owner,
                    aces,
                }
            }
            Err(e) => AclView::Err(e.to_string()),
        }
    }
}

fn find_by_sid<'a>(snap: &'a Snapshot, sid: &ldaphound_core::Sid) -> Option<&'a Object> {
    snap.objects
        .iter()
        .find(|o| o.object_sid().map(|s| &s == sid).unwrap_or(false))
}
