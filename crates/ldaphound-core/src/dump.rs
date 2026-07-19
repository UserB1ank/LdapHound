//! Snapshot rendering helpers used by the CLI (and reusable by the GUI
//! or any text export). Two output styles:
//!
//! - [`dump_object_ldap`]: `ldapsearch`-style attribute dump, one object
//!   per record (`dn:` line + `name: value` lines + blank separator).
//! - [`dump_object_acl`]: full ACL breakdown for one object — Owner/Group
//!   SIDs, control flags, and every ACE in the DACL with trustees resolved
//!   against the snapshot's object index.
//!
//! Both write to a caller-supplied [`Write`] sink so they work for stdout,
//! files, or in-memory buffers in tests.

use std::io::Write;

use crate::security::descriptor::SecurityDescriptor;
use crate::security::AceType;
use crate::{Object, Snapshot, Sid};

/// Emit one object in `ldapsearch`-style: `dn: ...` then every attribute as
/// `name: value`, terminated by a blank line. Multi-valued attributes emit
/// one line per value. Attributes are sorted alphabetically for stable diffs.
pub fn dump_object_ldap<W: Write>(obj: &Object, out: &mut W) -> std::io::Result<()> {
    writeln!(out, "dn: {}", obj.dn().unwrap_or(""))?;
    let mut names: Vec<&String> = obj.attributes.keys().collect();
    names.sort();
    for name in names {
        let attr = &obj.attributes[name];
        for value in &attr.values {
            writeln!(out, "{name}: {value}")?;
        }
    }
    writeln!(out)?;
    Ok(())
}

/// Dump a single object's attributes (LDAP-style) plus its full ACL breakdown.
///
/// Lines starting with `#` are comments / metadata (so they don't pollute
/// LDAP-style parsing of the attribute block). The ACL section resolves
/// trustee SIDs against the snapshot using a linear scan — fine for one-shot
/// CLI use; callers doing bulk resolution should build a `HashMap<Sid, &Object>`
/// (as the GUI does).
pub fn dump_object_acl<W: Write>(
    snap: &Snapshot,
    idx: usize,
    out: &mut W,
) -> std::io::Result<()> {
    let obj = &snap.objects[idx];
    writeln!(out, "# object index: {idx}")?;
    dump_object_ldap(obj, out)?;

    match obj.ntsd_bytes() {
        Some(bytes) => match SecurityDescriptor::from_bytes(bytes) {
            Ok(sd) => {
                writeln!(out, "# nTSecurityDescriptor breakdown:")?;
                writeln!(out, "#   bytes           : {}", bytes.len())?;
                writeln!(out, "#   revision        : {}", sd.revision)?;
                writeln!(out, "#   control_flags   : 0x{:04X}", sd.control_flags)?;
                writeln!(out, "#   dacl_protected  : {}", sd.is_dacl_protected())?;
                writeln!(
                    out,
                    "#   owner           : {}",
                    sd.owner.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                )?;
                writeln!(
                    out,
                    "#   group           : {}",
                    sd.group.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                )?;
                if let Some(dacl) = &sd.dacl {
                    writeln!(out, "#   DACL: revision={}, {} ACE(s)", dacl.revision, dacl.aces.len())?;
                    for (i, ace) in dacl.aces.iter().enumerate() {
                        let kind = match ace.ace_type() {
                            AceType::AccessAllowed => "Allow",
                            AceType::AccessDenied => "Deny",
                            AceType::AccessAllowedObject => "AllowObj",
                            AceType::AccessDeniedObject => "DenyObj",
                            _ => "Other",
                        };
                        let trustee = format_trustee(snap, ace.trustee());
                        let right = ace.right_name().unwrap_or_else(|| "-".into());
                        let mask = ace
                            .mask()
                            .map(|m| format!("{m} [{}]", m.human_names().join(",")))
                            .unwrap_or_else(|| "-".into());
                        let inherited = if ace.is_inherited() { "inherited" } else { "explicit" };
                        writeln!(
                            out,
                            "#     ACE[{i:>2}] {kind:<8} {right:<45} mask={mask} trustee={trustee} [{inherited}]"
                        )?;
                    }
                }
            }
            Err(e) => writeln!(out, "# nTSecurityDescriptor parse failed: {e}")?,
        },
        None => writeln!(out, "# (no nTSecurityDescriptor)")?,
    }
    Ok(())
}

/// Render a trustee SID. Resolves to `SID = displayName (class)` when the
/// SID belongs to an object in the snapshot, otherwise shows the bare SID.
fn format_trustee(snap: &Snapshot, sid: Option<&Sid>) -> String {
    let Some(sid) = sid else { return "-".into() };
    match find_by_sid(snap, sid) {
        Some(o) => format!(
            "{sid} = {} ({})",
            o.display_name(),
            o.object_classes().last().map(|s| s.as_str()).unwrap_or("?")
        ),
        None => format!("{sid} (unresolved)"),
    }
}

/// Find an object by SID via linear scan. Fine for one-shot CLI use; for
/// bulk lookups build a HashMap (as the GUI does).
fn find_by_sid<'a>(snap: &'a Snapshot, sid: &Sid) -> Option<&'a Object> {
    snap.objects
        .iter()
        .find(|o| o.object_sid().map(|s| &s == sid).unwrap_or(false))
}
