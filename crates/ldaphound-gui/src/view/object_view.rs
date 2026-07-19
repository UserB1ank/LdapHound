//! Right pane — selected object's details.
//!
//! Vertical stack inside one scrollable:
//! 1. Header (display name, objectClass, DN, SID)
//! 2. Attributes table (name | value), sorted alphabetically
//! 3. ACL breakdown (owner/group/flags + every ACE in the DACL, trustees
//!    resolved against the snapshot's object index)

use iced::widget::{column, container, row, scrollable, text};
use iced::{Element, Length};

use ldaphound_core::security::descriptor::SecurityDescriptor;
use ldaphound_core::{Object, Snapshot};

use crate::message::Message;

pub fn view<'a>(obj: &'a Object, snap: &'a Snapshot) -> Element<'a, Message> {
    // Collect owned strings up front so widgets don't borrow locals that
    // would be dropped at the end of this function.
    let title = format!(
        "{} ({})",
        obj.display_name(),
        obj.object_classes().last().map(|s| s.as_str()).unwrap_or("?"),
    );
    let dn_line = format!("dn: {}", obj.dn().unwrap_or(""));
    let sid_line = obj
        .object_sid()
        .map(|s| format!("sid: {s}"))
        .unwrap_or_default();

    let mut attrs: Vec<(&String, String)> = obj
        .attributes
        .iter()
        .map(|(k, a)| (k, format_attr_values(&a.values)))
        .collect();
    attrs.sort_by(|a, b| a.0.cmp(b.0));

    let acl = match obj.ntsd_bytes() {
        Some(b) => AclView::from_bytes(b, snap),
        None => AclView::Absent,
    };

    // Build widgets.
    let mut children: Vec<Element<'a, Message>> = Vec::new();
    children.push(text(title).size(16).into());
    children.push(text(dn_line).into());
    if !sid_line.is_empty() {
        children.push(text(sid_line).into());
    }

    // Attribute section.
    children.push(text(format!("Attributes ({})", attrs.len())).size(13).into());
    for (name, joined) in attrs {
        children.push(
            row![
                text(format!("{name}:")).width(Length::FillPortion(2)),
                text(joined).width(Length::FillPortion(5)),
            ]
            .spacing(8)
            .into(),
        );
    }

    // ACL section.
    match acl {
        AclView::Absent => children.push(text("(no nTSecurityDescriptor)").into()),
        AclView::Err(e) => children.push(text(format!("SD parse error: {e}")).into()),
        AclView::Ok {
            header,
            owner,
            ace_count,
            aces,
        } => {
            children.push(text(header).size(13).into());
            children.push(text(format!("owner: {owner}")).into());
            children.push(text(format!("DACL ({ace_count} ACEs):")).into());
            for ace in aces {
                children.push(
                    column![
                        text(ace.kind_line),
                        text(format!("    mask   : {}", ace.mask_line)),
                        text(format!("    trustee: {}", ace.trustee_line)),
                    ]
                    .spacing(2)
                    .into(),
                );
            }
        }
    }

    let col = column(children).spacing(6);
    container(scrollable(col))
        .width(Length::FillPortion(3))
        .height(Length::Fill)
        .padding(4)
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

// Owned ACL display data, decoupled from the borrowed SD parse result.
enum AclView {
    Absent,
    Err(String),
    Ok {
        header: String,
        owner: String,
        ace_count: usize,
        aces: Vec<AceLine>,
    },
}

struct AceLine {
    kind_line: String,
    mask_line: String,
    trustee_line: String,
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
                    .enumerate()
                    .map(|(i, ace)| {
                        use ldaphound_core::security::AceType;
                        let kind = match ace.ace_type() {
                            AceType::AccessAllowed => "Allow",
                            AceType::AccessDenied => "Deny",
                            AceType::AccessAllowedObject => "AllowObj",
                            AceType::AccessDeniedObject => "DenyObj",
                            _ => "Other",
                        };
                        let right = ace.right_name().unwrap_or_else(|| "-".into());
                        let inherited =
                            if ace.is_inherited() { "inherited" } else { "explicit" };
                        let mask = ace
                            .mask()
                            .map(|m| format!("{m} [{}]", m.human_names().join(",")))
                            .unwrap_or_else(|| "-".into());
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
                            kind_line: format!("▶ ACE[{i}] {kind} {right} [{inherited}]"),
                            mask_line: mask,
                            trustee_line: trustee,
                        }
                    })
                    .collect();
                AclView::Ok {
                    header,
                    owner,
                    ace_count: aces.len(),
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
