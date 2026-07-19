//! Right pane — selected object's ACL breakdown as a text tree.
//!
//! For each ACE in the DACL we render:
//!   ▶ <Allow|Deny> <right-name> [explicit|inherited]
//!       mask   : <hex + decoded flags>
//!       trustee: <SID> = <resolved-name (type)>
//!
//! Trustees are resolved via the SID→object index built at load time.
//!
//! Implementation note: we collect all display strings into owned data
//! first, then build the widget tree. This avoids lifetime entanglement
//! between the parsed `SecurityDescriptor` (a local) and the returned
//! `Element<'a>` (which borrows the snapshot).

use std::collections::HashMap;

use iced::widget::{column, container, scrollable, text};
use iced::{Element, Length};

use ldaphound_core::security::descriptor::SecurityDescriptor;
use ldaphound_core::{Object, Sid, Snapshot};

use crate::message::Message;

/// One ACE rendered as three text lines.
struct AceText {
    header: String,
    mask: String,
    trustee: String,
}

/// Render the ACL panel for one object.
pub fn view<'a>(
    obj: &'a Object,
    snap: &'a Snapshot,
    sid_index: &'a HashMap<Sid, usize>,
) -> Element<'a, Message> {
    // Gather owned display data up front so widgets don't borrow locals.
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

    // Pre-extract everything we want to display into owned strings.
    let mut sd_summary: Option<String> = None;
    let mut owner_line: String = String::new();
    let mut ace_texts: Vec<AceText> = Vec::new();
    let mut notice: Option<String> = None;

    if let Some(bytes) = obj.ntsd_bytes() {
        match SecurityDescriptor::from_bytes(bytes) {
            Ok(sd) => {
                sd_summary = Some(format!(
                    "SD: {} bytes, flags=0x{:04X}, DACL protected={}",
                    bytes.len(),
                    sd.control_flags,
                    sd.is_dacl_protected(),
                ));
                owner_line = format!(
                    "owner: {}",
                    sd.owner.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                );
                if let Some(dacl) = &sd.dacl {
                    for (i, ace) in dacl.aces.iter().enumerate() {
                        ace_texts.push(render_ace(i, ace, snap, sid_index));
                    }
                } else {
                    notice = Some("(no DACL)".into());
                }
            }
            Err(e) => notice = Some(format!("SD parse error: {e}")),
        }
    } else {
        notice = Some("(no nTSecurityDescriptor)".into());
    }

    // Now build the widget tree from owned data. Everything we push into the
    // column borrows only `Message` (zero-sized) — no local borrows remain.
    let mut children: Vec<Element<'a, Message>> = Vec::new();
    children.push(text(title).size(16).into());
    children.push(text(dn_line).into());
    if !sid_line.is_empty() {
        children.push(text(sid_line).into());
    }
    if let Some(s) = sd_summary {
        children.push(text(s).into());
    }
    if !owner_line.is_empty() {
        children.push(text(owner_line).into());
    }
    if !ace_texts.is_empty() {
        children.push(text(format!("DACL ({} ACEs):", ace_texts.len())).into());
        for ace in ace_texts {
            children.push(
                column![
                    text(ace.header),
                    text(format!("    mask   : {}", ace.mask)),
                    text(format!("    trustee: {}", ace.trustee)),
                ]
                .spacing(2)
                .into(),
            );
        }
    }
    if let Some(n) = notice {
        children.push(text(n).into());
    }

    let col = column(children).spacing(6);
    container(scrollable(col))
        .width(Length::FillPortion(3))
        .height(Length::Fill)
        .padding(4)
        .into()
}

fn render_ace(
    i: usize,
    ace: &ldaphound_core::security::Ace,
    snap: &Snapshot,
    sid_index: &HashMap<Sid, usize>,
) -> AceText {
    use ldaphound_core::security::AceType;

    let kind = match ace.ace_type() {
        AceType::AccessAllowed => "Allow",
        AceType::AccessDenied => "Deny",
        AceType::AccessAllowedObject => "AllowObj",
        AceType::AccessDeniedObject => "DenyObj",
        _ => "Other",
    };
    let right = ace.right_name().unwrap_or_else(|| "-".into());
    let inherited = if ace.is_inherited() { "inherited" } else { "explicit" };
    let mask = ace
        .mask()
        .map(|m| format!("{m} = [{}]", m.human_names().join(", ")))
        .unwrap_or_else(|| "-".into());

    let trustee = match ace.trustee() {
        Some(sid) => match sid_index.get(sid) {
            Some(&idx) => {
                let resolved = &snap.objects[idx];
                format!(
                    "{sid} = {} ({})",
                    resolved.display_name(),
                    resolved
                        .object_classes()
                        .last()
                        .map(|s| s.as_str())
                        .unwrap_or("?"),
                )
            }
            None => format!("{sid} (unresolved)"),
        },
        None => "(no trustee)".into(),
    };

    AceText {
        header: format!("▶ ACE[{i}] {kind} {right} [{inherited}]"),
        mask,
        trustee,
    }
}
