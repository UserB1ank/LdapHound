//! Access Control Entry (ACE). Spec §7.4.
//!
//! ACE types implemented: 0x00 (ACCESS_ALLOWED), 0x01 (ACCESS_DENIED),
//! 0x05 (ACCESS_ALLOWED_OBJECT), 0x06 (ACCESS_DENIED_OBJECT). Other types
//! fall through to [`Ace::Unknown`] with the raw bytes preserved.

use crate::error::{ParseError, Result};
use crate::guid::Guid;
use crate::security::access_mask::AccessMask;
use crate::security::object_type_guid;
use crate::sid::Sid;

/// ACE type byte. See spec §7.4 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceType {
    AccessAllowed,        // 0x00
    AccessDenied,         // 0x01
    SystemAudit,          // 0x02
    AccessAllowedObject,  // 0x05
    AccessDeniedObject,   // 0x06
    SystemAuditObject,    // 0x07
    Other(u8),
}

impl AceType {
    pub fn from_u8(b: u8) -> Self {
        match b {
            0x00 => Self::AccessAllowed,
            0x01 => Self::AccessDenied,
            0x02 => Self::SystemAudit,
            0x05 => Self::AccessAllowedObject,
            0x06 => Self::AccessDeniedObject,
            0x07 => Self::SystemAuditObject,
            other => Self::Other(other),
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Self::AccessAllowed | Self::AccessAllowedObject)
    }
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::AccessDenied | Self::AccessDeniedObject)
    }
}

/// ACE flags byte. Spec §7.4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AceFlags(pub u8);

impl AceFlags {
    pub const OBJECT_INHERIT: u8 = 0x01;
    pub const CONTAINER_INHERIT: u8 = 0x02;
    pub const NO_PROPAGATE_INHERIT: u8 = 0x04;
    pub const INHERIT_ONLY: u8 = 0x08;
    pub const INHERITED: u8 = 0x10;
    pub const SUCCESSFUL_ACCESS: u8 = 0x40;
    pub const FAILED_ACCESS: u8 = 0x80;

    pub fn is_inherited(&self) -> bool {
        self.0 & Self::INHERITED != 0
    }
}

/// Flags on object-type ACEs (0x05/0x06/0x07). Spec §7.6.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectFlags(pub u32);
impl ObjectFlags {
    pub const OBJECT_TYPE_PRESENT: u32 = 0x01;
    pub const INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x02;
}

/// One parsed ACE. Object variants carry optional ObjectType GUID which,
/// combined with the mask, yields a human-readable right name (spec §7.8).
#[derive(Debug, Clone)]
pub enum Ace {
    AccessAllowed {
        mask: AccessMask,
        flags: AceFlags,
        trustee: Sid,
    },
    AccessDenied {
        mask: AccessMask,
        flags: AceFlags,
        trustee: Sid,
    },
    AccessAllowedObject {
        mask: AccessMask,
        flags: AceFlags,
        object_flags: ObjectFlags,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
        trustee: Sid,
    },
    AccessDeniedObject {
        mask: AccessMask,
        flags: AceFlags,
        object_flags: ObjectFlags,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
        trustee: Sid,
    },
    /// Unsupported ACE type (callback, mandatory label, resource attribute,
    /// etc.). Raw body bytes preserved for diagnostics.
    Unknown {
        type_byte: u8,
        flags: AceFlags,
        raw: Vec<u8>,
    },
}

impl Ace {
    /// Parse one ACE from the given slice. Returns the ACE and the number
    /// of bytes consumed (always equal to the ACE's declared size).
    pub(crate) fn parse(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 4 {
            return Err(ParseError::Malformed {
                what: "ACE",
                detail: "header < 4 bytes".into(),
                offset: 0,
            });
        }
        let type_byte = bytes[0];
        let flags = AceFlags(bytes[1]);
        let ace_size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        if ace_size < 4 || bytes.len() < ace_size {
            return Err(ParseError::Malformed {
                what: "ACE",
                detail: format!("declared size {ace_size} invalid for input {}", bytes.len()),
                offset: 0,
            });
        }
        let body = &bytes[4..ace_size];
        let ace_type = AceType::from_u8(type_byte);

        let ace = match ace_type {
            AceType::AccessAllowed | AceType::AccessDenied | AceType::SystemAudit => {
                let mask = read_mask(body)?;
                let trustee = read_sid(&body[4..])?;
                if ace_type == AceType::AccessDenied {
                    Ace::AccessDenied { mask, flags, trustee }
                } else {
                    Ace::AccessAllowed { mask, flags, trustee }
                }
            }
            AceType::AccessAllowedObject | AceType::AccessDeniedObject => {
                // Layout: mask(4) + flags(4) + [object_type(16)] + [inherited_ot(16)] + sid
                if body.len() < 8 {
                    return Err(ParseError::Malformed {
                        what: "ACE",
                        detail: "object ACE body < 8 bytes".into(),
                        offset: 0,
                    });
                }
                let mask = read_mask(body)?;
                let object_flags = ObjectFlags(u32::from_le_bytes([
                    body[4], body[5], body[6], body[7],
                ]));
                let mut p = 8;
                let object_type = if object_flags.0 & ObjectFlags::OBJECT_TYPE_PRESENT != 0 {
                    let g = Guid::from_bytes(&body[p..p + 16])?;
                    p += 16;
                    Some(g)
                } else {
                    None
                };
                let inherited_object_type =
                    if object_flags.0 & ObjectFlags::INHERITED_OBJECT_TYPE_PRESENT != 0 {
                        let g = Guid::from_bytes(&body[p..p + 16])?;
                        p += 16;
                        Some(g)
                    } else {
                        None
                    };
                let trustee = read_sid(&body[p..])?;
                if ace_type == AceType::AccessDeniedObject {
                    Ace::AccessDeniedObject {
                        mask, flags, object_flags, object_type, inherited_object_type, trustee,
                    }
                } else {
                    Ace::AccessAllowedObject {
                        mask, flags, object_flags, object_type, inherited_object_type, trustee,
                    }
                }
            }
            AceType::SystemAuditObject | AceType::Other(_) => Ace::Unknown {
                type_byte,
                flags,
                raw: body.to_vec(),
            },
        };
        Ok((ace, ace_size))
    }

    pub fn trustee(&self) -> Option<&Sid> {
        match self {
            Ace::AccessAllowed { trustee, .. }
            | Ace::AccessDenied { trustee, .. } => Some(trustee),
            Ace::AccessAllowedObject { trustee, .. }
            | Ace::AccessDeniedObject { trustee, .. } => Some(trustee),
            Ace::Unknown { .. } => None,
        }
    }

    pub fn mask(&self) -> Option<AccessMask> {
        match self {
            Ace::AccessAllowed { mask, .. }
            | Ace::AccessDenied { mask, .. }
            | Ace::AccessAllowedObject { mask, .. }
            | Ace::AccessDeniedObject { mask, .. } => Some(*mask),
            Ace::Unknown { .. } => None,
        }
    }

    pub fn is_inherited(&self) -> bool {
        match self {
            Ace::AccessAllowed { flags, .. }
            | Ace::AccessDenied { flags, .. }
            | Ace::AccessAllowedObject { flags, .. }
            | Ace::AccessDeniedObject { flags, .. } => flags.is_inherited(),
            Ace::Unknown { flags, .. } => flags.is_inherited(),
        }
    }

    pub fn ace_type(&self) -> AceType {
        match self {
            Ace::AccessAllowed { .. } => AceType::AccessAllowed,
            Ace::AccessDenied { .. } => AceType::AccessDenied,
            Ace::AccessAllowedObject { .. } => AceType::AccessAllowedObject,
            Ace::AccessDeniedObject { .. } => AceType::AccessDeniedObject,
            Ace::Unknown { type_byte, .. } => AceType::Other(*type_byte),
        }
    }

    /// Best human-readable right name for this ACE, using the ObjectType
    /// GUID lookup table when the mask signals an extended right.
    pub fn right_name(&self) -> Option<String> {
        let mask = self.mask()?;
        if mask.is_extended() {
            if let Some(g) = self.object_type() {
                if let Some(nr) = object_type_guid::lookup_guid(&g) {
                    return Some(nr.name.to_string());
                }
                // Extended right with unknown GUID — return the GUID itself.
                return Some(format!("ExtendedRight({})", g));
            }
            return Some("ExtendedRight".into());
        }
        // Non-extended: prefer the most permissive single name.
        if mask.is_generic_all() {
            Some("GenericAll".into())
        } else if mask.is_write_dacl() {
            Some("WriteDACL".into())
        } else if mask.is_write_owner() {
            Some("WriteOwner".into())
        } else if mask.is_delete() {
            Some("Delete".into())
        } else if mask.is_write_property() {
            // If object_type is set it names the property being written.
            if let Some(g) = self.object_type() {
                if let Some(nr) = object_type_guid::lookup_guid(&g) {
                    return Some(format!("WriteProperty({})", nr.name));
                }
                return Some(format!("WriteProperty({})", g));
            }
            Some("WriteProperty".into())
        } else {
            mask.human_names().first().map(|s| s.to_string())
        }
    }

    fn object_type(&self) -> Option<&Guid> {
        match self {
            Ace::AccessAllowedObject { object_type, .. }
            | Ace::AccessDeniedObject { object_type, .. } => object_type.as_ref(),
            _ => None,
        }
    }
}

fn read_mask(body: &[u8]) -> Result<AccessMask> {
    if body.len() < 4 {
        return Err(ParseError::Malformed {
            what: "ACE",
            detail: "body < 4 bytes for mask".into(),
            offset: 0,
        });
    }
    Ok(AccessMask(u32::from_le_bytes([
        body[0], body[1], body[2], body[3],
    ])))
}

fn read_sid(body: &[u8]) -> Result<Sid> {
    if body.is_empty() {
        return Err(ParseError::Malformed {
            what: "ACE",
            detail: "no SID bytes".into(),
            offset: 0,
        });
    }
    let sub_count = body[1] as usize;
    let need = 8 + sub_count * 4;
    if body.len() < need {
        return Err(ParseError::Malformed {
            what: "ACE",
            detail: format!("SID needs {need} bytes, have {}", body.len()),
            offset: 0,
        });
    }
    Sid::from_bytes(&body[..need])
}
