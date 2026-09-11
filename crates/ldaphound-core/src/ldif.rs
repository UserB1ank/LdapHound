//! LDIF import — parse `ldapsearch` query results into a [`Snapshot`].
//!
//! LDIF (RFC 2849) is the text format `ldapsearch` writes: one record per
//! object (`dn:` line + `attribute: value` lines), records separated by
//! blank lines. Binary values (SID, GUID, `nTSecurityDescriptor`) arrive
//! base64-encoded after a double colon (`objectSid:: AQAA...`).
//!
//! Supported subset (everything OpenLDAP `ldapsearch` emits by default):
//! - comments (`#`) and the optional `version: 1` header
//! - folded lines (continuation lines start with a single space)
//! - `attr: value` plain and `attr:: base64` values
//! - CRLF line endings
//!
//! Not supported: `attr:< url` values (produced by `ldapsearch -t`, which
//! writes binary attributes to temp files — re-run without `-t` so values
//! stay inline), and change records (`changetype:` modify etc.).
//!
//! Values are typed the same way `.dat` attributes are: `nTSecurityDescriptor`
//! becomes [`AttributeValue::NtSecurityDescriptor`], known binary attributes
//! become `OctetString`, and everything else stays a string — so the tree,
//! filter, ACL and trustee-resolution layers all work unchanged on LDIF
//! imports.

use std::collections::HashMap;

use crate::error::{ParseError, Result};
use crate::snapshot::Snapshot;
use crate::snapshot::attribute::{Attribute, AttributeValue};
use crate::snapshot::header::Header;
use crate::snapshot::object::Object;

/// Placeholder server name shown in the GUI title / CLI summary when the
/// snapshot was imported from LDIF (the LDAP server hostname isn't recorded
/// in the LDIF itself).
pub const LDIF_SERVER_NAME: &str = "ldapsearch (LDIF)";

/// Attributes that are always binary (octet string) in AD, regardless of
/// what the bytes happen to look like. Needed because SIDs and GUIDs are
/// often pure ASCII+NUL bytes that would otherwise decode as "valid UTF-8".
const BINARY_ATTRS: &[&str] = &[
    "objectsid",
    "objectguid",
    "sidhistory",
    "schemaidguid",
    "attributesecurityguids",
    "msds-generationid",
    "thumbnailphoto",
    "jpegphoto",
    "usercertificate",
    "cacertificate",
];

/// One record in raw form: the `dn:` line plus unfolded attribute lines
/// with their source line numbers (for error context).
type RawRecord = (String, Vec<RawAttr>);

/// (attribute name, value spec, physical line number).
type RawAttr = (String, ValueSpec, usize);

impl Snapshot {
    /// Build a snapshot from LDIF text (e.g. a saved `ldapsearch` result).
    /// The header is synthetic: there is no server hostname or timestamp in
    /// LDIF, and properties/property_index stay empty (LDIF attribute names
    /// travel with each record).
    pub fn from_ldif_str(text: &str) -> Result<Self> {
        let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        let objects = parse_ldif(text)?;
        Ok(Self {
            header: Header {
                server: LDIF_SERVER_NAME.to_string(),
                filetime: 0,
                num_objects: objects.len() as u32,
                metadata_offset: 0,
                treeview_offset: 0,
            },
            properties: Vec::new(),
            property_index: HashMap::new(),
            objects,
        })
    }
}

/// One unfolded source line with the physical line number it started on
/// (for error reporting).
struct LogicalLine {
    text: String,
    line_no: usize,
}

/// Split input into unfolded logical lines: a physical line starting with a
/// single space continues the previous line. Trailing `\r` (CRLF input) is
/// stripped. Comments are kept here and filtered by the caller (folding a
/// comment line is legal, so unfold first, then check `#`).
fn logical_lines(input: &str) -> Result<Vec<LogicalLine>> {
    let mut out: Vec<LogicalLine> = Vec::new();
    for (i, raw) in input.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = line.strip_prefix(' ') {
            match out.last_mut() {
                Some(prev) => prev.text.push_str(rest),
                None => {
                    return Err(ParseError::Malformed {
                        what: "LDIF",
                        detail: "continuation line with nothing to continue".into(),
                        offset: (i + 1) as u64,
                    });
                }
            }
        } else {
            out.push(LogicalLine {
                text: line.to_string(),
                line_no: i + 1,
            });
        }
    }
    Ok(out)
}

/// How a value was encoded on its LDIF line.
enum ValueSpec {
    /// After `attr: ` — verbatim text.
    Plain(String),
    /// After `attr:: ` — base64 payload.
    Base64(String),
}

/// Split `attr: value` / `attr:: base64`. Returns the attribute name and
/// the value spec. `attr:< url` is rejected with a hint (`ldapsearch -t`).
fn split_attr_line(line: &LogicalLine) -> Result<(String, ValueSpec)> {
    let err = |detail: String| ParseError::Malformed {
        what: "LDIF",
        detail,
        offset: line.line_no as u64,
    };
    let colon = line
        .text
        .find(':')
        .ok_or_else(|| err(format!("expected 'attr: value', got {:?}", line.text)))?;
    let name = line.text[..colon].to_string();
    if name.is_empty() {
        return Err(err("empty attribute name".into()));
    }
    let after = &line.text[colon + 1..];
    if let Some(b64) = after.strip_prefix(':') {
        // `::` — one separator space, then base64.
        let payload = b64.strip_prefix(' ').unwrap_or(b64);
        Ok((name, ValueSpec::Base64(payload.to_string())))
    } else if after.starts_with('<') {
        Err(err(
            "URL values (attr:< file://...) are not supported — re-run \
             ldapsearch without -t so values stay inline"
                .into(),
        ))
    } else {
        // `:` — one separator space, then verbatim value.
        let value = after.strip_prefix(' ').unwrap_or(after);
        Ok((name, ValueSpec::Plain(value.to_string())))
    }
}

/// Convert one LDIF value into the typed [`AttributeValue`] the rest of the
/// codebase expects. See the module docs for the typing rules.
fn convert_value(name: &str, spec: ValueSpec, line_no: usize) -> Result<AttributeValue> {
    let b64 = match spec {
        ValueSpec::Plain(s) => return Ok(AttributeValue::String(s)),
        ValueSpec::Base64(b) => b,
    };
    let bytes = base64_decode(&b64, line_no)?;
    let lower = name.to_ascii_lowercase();
    if lower == "ntsecuritydescriptor" {
        return Ok(AttributeValue::NtSecurityDescriptor(bytes));
    }
    if BINARY_ATTRS.contains(&lower.as_str()) {
        return Ok(AttributeValue::OctetString(bytes));
    }
    // Base64 is also used for non-ASCII *text* values, so fall back to a
    // string when the bytes are clean UTF-8. NUL bytes never appear in LDAP
    // string values but do appear in binary ones — use them as the tell.
    match std::str::from_utf8(&bytes) {
        Ok(s) if !s.contains('\0') => Ok(AttributeValue::String(s.to_string())),
        _ => Ok(AttributeValue::OctetString(bytes)),
    }
}

/// Parse LDIF text into objects. Records are separated by blank lines and
/// must start with a `dn:` line. A `distinguishedName` attribute is
/// synthesized from the `dn:` line when the record doesn't carry one (the
/// tree builder and filters read it).
fn parse_ldif(input: &str) -> Result<Vec<Object>> {
    let mut objects = Vec::new();
    let mut current: Option<RawRecord> = None;

    for line in logical_lines(input)? {
        if line.text.is_empty() || line.text.chars().all(char::is_whitespace) {
            flush(&mut objects, &mut current)?;
            continue;
        }
        if line.text.starts_with('#') {
            continue;
        }
        let (name, spec) = split_attr_line(&line)?;

        // Be lenient about a missing blank line between records: a fresh
        // `dn:` always starts a new record.
        if current.is_some() && name.eq_ignore_ascii_case("dn") {
            flush(&mut objects, &mut current)?;
        }

        let Some(rec) = current.as_mut() else {
            if name.eq_ignore_ascii_case("version") && objects.is_empty() {
                continue; // `version: 1` header
            }
            if !name.eq_ignore_ascii_case("dn") {
                return Err(ParseError::Malformed {
                    what: "LDIF",
                    detail: format!("record must start with 'dn:', got '{name}:'"),
                    offset: line.line_no as u64,
                });
            }
            let dn = match spec {
                ValueSpec::Plain(s) => s,
                ValueSpec::Base64(b64) => {
                    let bytes = base64_decode(&b64, line.line_no)?;
                    String::from_utf8(bytes).map_err(|_| ParseError::Malformed {
                        what: "LDIF",
                        detail: "base64 'dn' is not valid UTF-8".into(),
                        offset: line.line_no as u64,
                    })?
                }
            };
            current = Some((dn, Vec::new()));
            continue;
        };
        rec.1.push((name, spec, line.line_no));
    }
    flush(&mut objects, &mut current)?;
    Ok(objects)
}

/// Finish the current record, if any, turning it into an [`Object`].
fn flush(objects: &mut Vec<Object>, current: &mut Option<RawRecord>) -> Result<()> {
    if let Some((dn, attrs)) = current.take() {
        objects.push(build_object(&dn, attrs)?);
    }
    Ok(())
}

/// Assemble one [`Object`] from a raw record.
fn build_object(dn: &str, attrs: Vec<RawAttr>) -> Result<Object> {
    let mut attributes: HashMap<String, Attribute> = HashMap::with_capacity(attrs.len() + 1);
    for (name, spec, line_no) in attrs {
        let value = convert_value(&name, spec, line_no)?;
        attributes
            .entry(name)
            .or_insert_with(|| Attribute { values: Vec::new() })
            .values
            .push(value);
    }
    // The dn: line is always present in a record; mirror it into a
    // distinguishedName attribute when the query didn't request one.
    let has_dn_attr = attributes
        .keys()
        .any(|k| k.eq_ignore_ascii_case("distinguishedName"));
    if !has_dn_attr {
        attributes.insert(
            "distinguishedName".to_string(),
            Attribute {
                values: vec![AttributeValue::String(dn.to_string())],
            },
        );
    }
    Ok(Object { attributes })
}

/// Decode standard-alphabet base64 (with `=` padding). Internal whitespace
/// is ignored (defensive; folding is normally unfolded before this runs).
fn base64_decode(input: &str, line_no: usize) -> Result<Vec<u8>> {
    let err = |detail: &str| ParseError::Malformed {
        what: "LDIF",
        detail: format!("invalid base64 ({detail}) on line {line_no}"),
        offset: line_no as u64,
    };
    let chars: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    // Not `!chars.len().is_multiple_of(4)`: that API needs Rust 1.87, and
    // the project's MSRV is 1.85.
    #[allow(clippy::manual_is_multiple_of)]
    if chars.len() % 4 != 0 {
        return Err(err("length not a multiple of 4"));
    }
    let sextet = |c: u8| -> Result<u8> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(err("invalid character")),
        }
    };
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    for group in chars.chunks(4) {
        let mut pads = 0usize;
        let mut vals = [0u8; 4];
        for (i, &c) in group.iter().enumerate() {
            if c == b'=' {
                pads += 1;
            } else {
                if pads > 0 {
                    return Err(err("data after padding"));
                }
                vals[i] = sextet(c)?;
            }
        }
        if pads > 2 {
            return Err(err("misplaced padding"));
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | vals[3] as u32;
        out.push((n >> 16) as u8);
        if pads < 2 {
            out.push((n >> 8) as u8);
        }
        if pads < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only encoder so fixtures can be built from raw bytes without
    /// hand-computing base64.
    fn b64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// Raw bytes of a SID like S-1-5-21-1-2-3: revision + sub-authority
    /// count, 6-byte big-endian identifier authority, LE sub-authorities.
    fn sid_bytes(sub: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, sub.len() as u8];
        v.extend_from_slice(&5u64.to_be_bytes()[2..]); // authority 5, 6 bytes
        for s in sub {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_decode("QQ==", 1).unwrap(), b"A");
        assert_eq!(base64_decode("QUI=", 1).unwrap(), b"AB");
        assert_eq!(base64_decode("QUJD", 1).unwrap(), b"ABC");
        assert_eq!(base64_decode("QUJDRA==", 1).unwrap(), b"ABCD");
        assert!(base64_decode("QUJD!", 1).is_err()); // invalid char
        assert!(base64_decode("QQ=", 1).is_err()); // bad length
        assert!(base64_decode("=QJD", 1).is_err()); // pad then data
        assert!(base64_decode("Q===", 1).is_err()); // too much padding
        // Round-trip against the test encoder.
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(base64_decode(&b64(&data), 1).unwrap(), data);
    }

    #[test]
    fn parses_simple_record() {
        let ldif = "\
# search result
dn: CN=jdoe,CN=Users,DC=corp,DC=local
objectClass: top
objectClass: person
objectClass: user
sAMAccountName: jdoe
userAccountControl: 512

";
        let objs = parse_ldif(ldif).unwrap();
        assert_eq!(objs.len(), 1);
        let o = &objs[0];
        assert_eq!(
            o.get_first("distinguishedName").and_then(|v| v.as_str()),
            Some("CN=jdoe,CN=Users,DC=corp,DC=local")
        );
        // objectClass assembled multi-valued from repeated lines.
        assert_eq!(o.get("objectClass").map(|a| a.values.len()), Some(3));
        assert!(o.has_class("person"));
        assert_eq!(o.object_type(), crate::filter::ObjectType::User);
    }

    #[test]
    fn base64_sid_becomes_octet_string() {
        let sid = sid_bytes(&[21, 1, 2, 3]); // S-1-5-21-1-2-3
        let ldif = format!("dn: CN=x,DC=corp,DC=local\nobjectSid:: {}\n", b64(&sid));
        let objs = parse_ldif(&ldif).unwrap();
        assert_eq!(objs[0].object_sid().unwrap().to_string(), "S-1-5-21-1-2-3");
    }

    #[test]
    fn base64_sd_becomes_ntsd() {
        let sd: Vec<u8> = (0..40u8).collect(); // opaque bytes; SD parse not needed here
        let ldif = format!(
            "dn: CN=x,DC=corp,DC=local\nnTSecurityDescriptor:: {}\n",
            b64(&sd)
        );
        let objs = parse_ldif(&ldif).unwrap();
        assert_eq!(objs[0].ntsd_bytes(), Some(&sd[..]));
    }

    #[test]
    fn base64_non_ascii_text_becomes_string() {
        // A CN with non-ASCII characters: ldapsearch emits it as base64.
        let ldif = format!("dn: CN=x,DC=a\nname:: {}\n", b64("张三".as_bytes()));
        let objs = parse_ldif(&ldif).unwrap();
        assert_eq!(
            objs[0].get_first("name").and_then(|v| v.as_str()),
            Some("张三")
        );
        assert_eq!(objs[0].display_name(), "张三");
    }

    #[test]
    fn ascii_bytes_with_nul_stay_octet() {
        // Bytes that are valid UTF-8 *and* all-ASCII but contain NULs
        // (e.g. some GUIDs/SIDs) must not be turned into strings.
        let bytes = b"\x01\x04\x00\x00\x00\x00\x00\x05".to_vec();
        let ldif = format!("dn: CN=x,DC=a\nsomeBlob:: {}\n", b64(&bytes));
        let objs = parse_ldif(&ldif).unwrap();
        assert!(objs[0].get_first("someBlob").unwrap().as_str().is_none());
    }

    #[test]
    fn unfolds_folded_lines() {
        // Continuation strips exactly one separator space; any further
        // leading spaces are content (RFC 2849 folding semantics).
        let ldif = "dn: CN=x,DC=a\ndescription: a very long\n  folded value\n";
        let objs = parse_ldif(ldif).unwrap();
        assert_eq!(
            objs[0].get_first("description").and_then(|v| v.as_str()),
            Some("a very long folded value")
        );
    }

    #[test]
    fn crlf_and_version_header() {
        let ldif = "version: 1\r\n\r\ndn: DC=a\r\nobjectClass: domain\r\n\r\n";
        let objs = parse_ldif(ldif).unwrap();
        assert_eq!(objs.len(), 1);
        assert!(objs[0].has_class("domain"));
    }

    #[test]
    fn multiple_records_and_dn_without_blank_line() {
        let ldif = "dn: CN=a,DC=x\ncn: a\ndn: CN=b,DC=x\ncn: b\n";
        let objs = parse_ldif(ldif).unwrap();
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[1].get_first("cn").and_then(|v| v.as_str()), Some("b"));
    }

    #[test]
    fn rejects_record_without_dn() {
        assert!(parse_ldif("cn: orphan\n").is_err());
        assert!(parse_ldif("no colon here\n").is_err());
    }

    #[test]
    fn rejects_url_values_with_hint() {
        let err = parse_ldif("dn: DC=a\nthumbnailPhoto:< file:///tmp/ldapsearchXYZ\n").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("without -t"), "got: {msg}");
    }

    #[test]
    fn snapshot_from_ldif_builds_tree() {
        // A tiny domain: root + a Users container + one user child. The root
        // carries a real SID so the tree builder recognizes the Domain NC head.
        let root_sid = b64(&sid_bytes(&[21, 1, 1, 1]));
        let ldif = format!(
            "dn: DC=corp,DC=local\nobjectClass: top\nobjectClass: domain\n\
             objectSid:: {root_sid}\n\
             name: corp.local\n\n\
             dn: CN=Users,DC=corp,DC=local\nobjectClass: container\n\n\
             dn: CN=jdoe,CN=Users,DC=corp,DC=local\nobjectClass: top\n\
             objectClass: person\nobjectClass: user\nsAMAccountName: jdoe\n\n"
        );
        let snap = Snapshot::from_ldif_str(&ldif).unwrap();
        assert_eq!(snap.objects.len(), 3);
        assert_eq!(snap.header.server, LDIF_SERVER_NAME);
        assert_eq!(snap.header.num_objects, 3);
        let tree = snap.build_tree();
        assert_eq!(tree.roots.len(), 1); // domain NC, nothing orphaned
        let users_node = &tree.roots[0].children[0]; // CN=Users container
        assert_eq!(users_node.children.len(), 1); // jdoe parented under it
    }

    #[test]
    fn ldap_filter_matches_ldif_objects() {
        let ldif = "\
dn: CN=jdoe,CN=Users,DC=corp,DC=local
objectClass: user
sAMAccountName: jdoe
userAccountControl: 512

dn: CN=WS01$,CN=Computers,DC=corp,DC=local
objectClass: computer
sAMAccountName: WS01$

";
        let snap = Snapshot::from_ldif_str(ldif).unwrap();
        let f = crate::filter::LdapFilter::parse("(objectClass=user)").unwrap();
        let users: Vec<_> = snap.objects.iter().filter(|o| f.matches(o)).collect();
        assert_eq!(users.len(), 1);
        // Numeric equality works on string values (filter fast path).
        let g = crate::filter::LdapFilter::parse("(userAccountControl=512)").unwrap();
        assert!(g.matches(&snap.objects[0]));
    }

    #[test]
    fn load_bytes_dispatches_by_signature() {
        use crate::snapshot::header::WIN_AD_SIG;
        // Signature match → binary parser (truncated garbage makes it fail
        // with a binary-path error — BadSignature or EOF — never an LDIF
        // parse error, which is what proves the dispatch).
        let mut dat = WIN_AD_SIG.as_slice().to_vec();
        dat.extend_from_slice(&[0u8; 8]);
        match Snapshot::load_bytes(&dat) {
            Err(crate::ParseError::BadSignature { .. })
            | Err(crate::ParseError::UnexpectedEof { .. }) => {}
            other => panic!("expected a binary-path error, got {other:?}"),
        }
        // No signature → LDIF path.
        let snap = Snapshot::load_bytes(b"dn: DC=a\nobjectClass: domain\n").unwrap();
        assert_eq!(snap.objects.len(), 1);
        assert_eq!(snap.header.server, LDIF_SERVER_NAME);
        // Neither dat nor UTF-8 → Unrecognized.
        assert!(matches!(
            Snapshot::load_bytes(&[0xff, 0xfe, 0x00, 0x01]),
            Err(crate::ParseError::Unrecognized(_))
        ));
    }
}
