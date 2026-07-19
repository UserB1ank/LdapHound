//! Attribute values, dispatched by `ads_type`. Spec §3.
//!
//! Every attribute starts with `u32 numValues`. The bytes that follow depend
//! on the property's `ads_type`:
//! - String-like (1/2/3/4/5/12): offset table (relative to attribute start)
//!   then null-terminated UTF-16LE strings.
//! - OctetString (8): length table then raw bytes. SID/GUID live here.
//! - NT_SECURITY_DESCRIPTOR (25): u32 length + raw SD bytes (GUI core).
//! - Integer/Boolean/LargeInteger/UtcTime: inline values.

use crate::error::{ParseError, Result};
use crate::le_reader::LeReader;
use crate::snapshot::property::AdsType;

/// One attribute's values. AD attributes can be multi-valued.
#[derive(Debug, Clone)]
pub struct Attribute {
    pub values: Vec<AttributeValue>,
}

/// A single attribute value, parsed into the most useful Rust type for its
/// ads_type. OctetString values are kept as raw bytes; the caller decides
/// whether to interpret them as SID/GUID (based on attribute name).
#[derive(Debug, Clone)]
pub enum AttributeValue {
    String(String),
    Integer(u32),
    LargeInteger(i64),
    Boolean(bool),
    OctetString(Vec<u8>),
    NtSecurityDescriptor(Vec<u8>),
    /// Unix timestamp (seconds since 1970-01-01 UTC).
    UtcTime(i64),
}

impl Attribute {
    /// Parse an attribute value block located at the current cursor.
    ///
    /// `attr_start` is the cursor position when this method was entered; it
    /// is used as the base for the string-type offset table. `ads_type` comes
    /// from the matching `Property` (looked up by `attr_index` in the object's
    /// mapping table).
    pub(crate) fn parse(
        r: &mut LeReader<'_>,
        attr_start: u64,
        ads_type: AdsType,
    ) -> Result<Self> {
        let num_values = r.read_u32()? as usize;
        let values = match ads_type {
            AdsType::Boolean => {
                let mut out = Vec::with_capacity(num_values);
                for _ in 0..num_values {
                    out.push(AttributeValue::Boolean(r.read_u32()? != 0));
                }
                out
            }
            AdsType::Integer => {
                let mut out = Vec::with_capacity(num_values);
                for _ in 0..num_values {
                    out.push(AttributeValue::Integer(r.read_u32()?));
                }
                out
            }
            AdsType::LargeInteger => {
                let mut out = Vec::with_capacity(num_values);
                for _ in 0..num_values {
                    out.push(AttributeValue::LargeInteger(r.read_i64()?));
                }
                out
            }
            AdsType::OctetString => {
                let mut lengths = Vec::with_capacity(num_values);
                for _ in 0..num_values {
                    lengths.push(r.read_u32()? as usize);
                }
                let mut out = Vec::with_capacity(num_values);
                for len in lengths {
                    out.push(AttributeValue::OctetString(r.read_bytes(len)?));
                }
                out
            }
            AdsType::NtSecurityDescriptor => {
                // Per spec §3.2 type 25: u32 length + raw bytes.
                // Multiple SD values is unusual but possible; handle uniformly.
                let mut out = Vec::with_capacity(num_values);
                for _ in 0..num_values {
                    let len = r.read_u32()? as usize;
                    out.push(AttributeValue::NtSecurityDescriptor(r.read_bytes(len)?));
                }
                out
            }
            AdsType::UtcTime => {
                let mut out = Vec::with_capacity(num_values);
                for _ in 0..num_values {
                    out.push(AttributeValue::UtcTime(read_systemtime(r)?));
                }
                out
            }
            // String-like types all share the offset-table layout (spec §3.4).
            AdsType::DnString
            | AdsType::CaseExactString
            | AdsType::CaseIgnoreString
            | AdsType::PrintableString
            | AdsType::NumericString
            | AdsType::ObjectClass => {
                // Offset table relative to attr_start.
                let mut offsets = Vec::with_capacity(num_values);
                for _ in 0..num_values {
                    offsets.push(r.read_u32()? as u64);
                }
                let saved_pos = r.pos();
                let mut out = Vec::with_capacity(num_values);
                for off in offsets {
                    r.seek(attr_start + off)?;
                    out.push(AttributeValue::String(r.read_wstring_until_null()?));
                }
                // Restore cursor so subsequent mapping entries parse correctly.
                r.seek(saved_pos)?;
                out
            }
            AdsType::Other(raw) => {
                return Err(ParseError::UnhandledAdsType {
                    ads_type: raw,
                    attr: String::new(),
                    offset: attr_start,
                });
            }
        };
        Ok(Self { values })
    }
}

/// Parse a 16-byte SYSTEMTIME (spec §3.3) into a Unix timestamp.
fn read_systemtime(r: &mut LeReader<'_>) -> Result<i64> {
    let year = r.read_u16()? as i32;
    let _month = r.read_u16()? as u32;
    let _day_of_week = r.read_u16()?;
    let _day = r.read_u16()?;
    let _hour = r.read_u16()?;
    let _minute = r.read_u16()?;
    let _second = r.read_u16()?;
    let _ms = r.read_u16()?;
    // Full conversion requires civil_from_days math; for now only the year
    // is validated. The GUI mostly cares about LargeInteger (FILETIME) times,
    // which is the common case for `lastLogon` etc. SYSTEMTIME appears on
    // `whenCreated`-style attributes.
    if year < 1601 || year > 9999 {
        return Err(ParseError::Malformed {
            what: "SYSTEMTIME",
            detail: format!("year {year} out of range"),
            offset: r.pos() - 16,
        });
    }
    // TODO: full civil-from-days conversion. Returning 0 for now; tests will
    // pin this once the algorithm is added.
    Ok(0)
}

impl AttributeValue {
    pub fn as_str(&self) -> Option<&str> {
        if let AttributeValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_integer(&self) -> Option<u32> {
        if let AttributeValue::Integer(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    /// As a Windows FILETIME-style LargeInteger converted to Unix seconds,
    /// or a stored UtcTime. Useful for `lastLogon`/`pwdLastSet`.
    pub fn as_unix_timestamp(&self) -> Option<i64> {
        match self {
            AttributeValue::LargeInteger(t) => {
                if *t == 0 || *t == i64::MAX {
                    return Some(0);
                }
                Some(((*t as i128 - 116444736000000000) / 10_000_000) as i64)
            }
            AttributeValue::UtcTime(t) => Some(*t),
            _ => None,
        }
    }

    /// If this is an OctetString and the caller wants SID/GUID bytes.
    pub fn as_octet_bytes(&self) -> Option<&[u8]> {
        match self {
            AttributeValue::OctetString(b) => Some(b),
            AttributeValue::NtSecurityDescriptor(b) => Some(b),
            _ => None,
        }
    }

    /// If this is an NT_SECURITY_DESCRIPTOR value, return its bytes.
    pub fn as_nt_security_descriptor(&self) -> Option<&[u8]> {
        if let AttributeValue::NtSecurityDescriptor(b) = self {
            Some(b)
        } else {
            None
        }
    }
}

impl std::fmt::Display for AttributeValue {
    /// Best-effort single-line display for `ldapsearch`-style output.
    /// Octet strings render as hex; large blobs (NT SD) are truncated with
    /// a byte count. Callers needing structured access (SID/GUID/SD) should
    /// match on the variant instead of using this display.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttributeValue::String(s) => f.write_str(s),
            AttributeValue::Integer(i) => write!(f, "{i}"),
            AttributeValue::LargeInteger(i) => write!(f, "{i}"),
            AttributeValue::Boolean(b) => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            AttributeValue::UtcTime(t) => write!(f, "{t}"),
            AttributeValue::OctetString(b) => write_hex(f, b),
            AttributeValue::NtSecurityDescriptor(b) => {
                if b.len() > 64 {
                    write!(f, "<{} bytes>", b.len())
                } else {
                    write_hex(f, b)
                }
            }
        }
    }
}

fn write_hex(f: &mut std::fmt::Formatter<'_>, b: &[u8]) -> std::fmt::Result {
    f.write_str("0x")?;
    for byte in b {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}
