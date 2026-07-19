//! Property (schema attribute definition). Spec §4.
//!
//! Each Property describes one LDAP attribute: its name, value type
//! (`ads_type`, drives attribute parsing — see spec §3.2), schema DN,
//! and a GUID used to resolve ACE ObjectTypes.

use crate::error::Result;
use crate::guid::Guid;
use crate::le_reader::LeReader;

/// ADSTYPE enum subset relevant to LdapHound. Unknown values map to `Other`.
/// See spec §3.2 for the value-layout each variant implies.
///
/// Note: we don't use `#[repr(u32)]` + explicit discriminants because Rust
/// forbids explicit discriminants on enums with non-unit variants. Use
/// [`AdsType::from_u32`] / [`AdsType::raw`] for the wire value instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdsType {
    DnString,
    CaseExactString,
    CaseIgnoreString,
    PrintableString,
    NumericString,
    Boolean,
    Integer,
    OctetString,
    UtcTime,
    LargeInteger,
    ObjectClass,
    NtSecurityDescriptor,
    Other(u32),
}

impl AdsType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::DnString,
            2 => Self::CaseExactString,
            3 => Self::CaseIgnoreString,
            4 => Self::PrintableString,
            5 => Self::NumericString,
            6 => Self::Boolean,
            7 => Self::Integer,
            8 => Self::OctetString,
            9 => Self::UtcTime,
            10 => Self::LargeInteger,
            12 => Self::ObjectClass,
            25 => Self::NtSecurityDescriptor,
            other => Self::Other(other),
        }
    }

    /// True if this type stores string values (offset table + UTF-16LE).
    pub fn is_string_like(&self) -> bool {
        matches!(
            self,
            Self::DnString
                | Self::CaseExactString
                | Self::CaseIgnoreString
                | Self::PrintableString
                | Self::NumericString
                | Self::ObjectClass
        )
    }

    pub fn raw(&self) -> u32 {
        match self {
            Self::DnString => 1,
            Self::CaseExactString => 2,
            Self::CaseIgnoreString => 3,
            Self::PrintableString => 4,
            Self::NumericString => 5,
            Self::Boolean => 6,
            Self::Integer => 7,
            Self::OctetString => 8,
            Self::UtcTime => 9,
            Self::LargeInteger => 10,
            Self::ObjectClass => 12,
            Self::NtSecurityDescriptor => 25,
            Self::Other(v) => *v,
        }
    }
}

/// A property definition from the Properties segment.
#[derive(Debug, Clone)]
pub struct Property {
    /// LDAP attribute name (e.g. `accountExpires`, `nTSecurityDescriptor`).
    pub name: String,
    /// Value type, drives attribute parsing.
    pub ads_type: AdsType,
    /// Schema DN (e.g. `CN=Account-Expires,CN=Schema,...`).
    pub dn: String,
    /// Schema ID GUID — used to resolve ACE ObjectTypes (spec §7.8).
    pub schema_id_guid: Guid,
}

impl Property {
    /// Parse one property. Cursor advances past the trailing 4-byte blob.
    pub(crate) fn parse(r: &mut LeReader<'_>) -> Result<Self> {
        // u32 lenPropName (in bytes) + wchar[len/2]
        let name = r.read_wstring_prefixed()?;
        // i32 unk1 — purpose unknown, value 4 observed on 0718.dat.
        let _unk1 = r.read_i32()?;
        // u32 adsType
        let ads_type = AdsType::from_u32(r.read_u32()?);
        // u32 lenDN + wchar[len/2]
        let dn = r.read_wstring_prefixed()?;
        // char[16] schemaIDGUID
        let guid_bytes = r.read_bytes_ref(16)?;
        let schema_id_guid = Guid::from_bytes(guid_bytes)?;
        // char[16] attributeSecurityGUID — currently unused, skip.
        r.skip(16)?;
        // char[4] blob — purpose unknown.
        r.skip(4)?;
        Ok(Self {
            name,
            ads_type,
            dn,
            schema_id_guid,
        })
    }
}
