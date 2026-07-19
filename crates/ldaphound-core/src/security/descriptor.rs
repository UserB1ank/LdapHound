//! Security Descriptor. Spec §7.1.
//!
//! Self-relative form as stored in `nTSecurityDescriptor`. All offsets are
//! relative to the start of the SD buffer.

use crate::error::{ParseError, Result};
use crate::security::acl::Acl;
use crate::sid::Sid;

/// Bit flags in the SD header's ControlFlags field (spec §7.2).
pub mod control_flag {
    pub const SR: u16 = 0x8000;
    pub const RM: u16 = 0x4000;
    pub const PS: u16 = 0x2000; // SACL protected
    pub const PD: u16 = 0x1000; // DACL protected
    pub const SI: u16 = 0x0800;
    pub const DI: u16 = 0x0400;
    pub const SC: u16 = 0x0200;
    pub const DC: u16 = 0x0100;
    pub const SS: u16 = 0x0080;
    pub const DT: u16 = 0x0040;
    pub const SD: u16 = 0x0020;
    pub const SP: u16 = 0x0010; // SACL present
    pub const DD: u16 = 0x0008;
    pub const DP: u16 = 0x0004; // DACL present
    pub const GD: u16 = 0x0002;
    pub const OD: u16 = 0x0001;
}

/// A self-relative security descriptor.
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub control_flags: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// Parse from the raw SD bytes (as stored in `nTSecurityDescriptor`).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 20 {
            return Err(ParseError::Malformed {
                what: "SD",
                detail: format!("header < 20 bytes (got {})", b.len()),
                offset: 0,
            });
        }
        let revision = b[0];
        // sbz1 at [1] ignored
        let control_flags = u16::from_le_bytes([b[2], b[3]]);
        let off_owner = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize;
        let off_group = u32::from_le_bytes([b[8], b[9], b[10], b[11]]) as usize;
        let off_sacl = u32::from_le_bytes([b[12], b[13], b[14], b[15]]) as usize;
        let off_dacl = u32::from_le_bytes([b[16], b[17], b[18], b[19]]) as usize;

        let owner = if off_owner != 0 && off_owner < b.len() {
            Some(read_sid_at(b, off_owner)?)
        } else {
            None
        };
        let group = if off_group != 0 && off_group < b.len() {
            Some(read_sid_at(b, off_group)?)
        } else {
            None
        };
        // DACL is only meaningful when DP (DACL present) is set.
        let dacl = if (control_flags & control_flag::DP) != 0
            && off_dacl != 0
            && off_dacl < b.len()
        {
            Some(Acl::parse(&b[off_dacl..])?)
        } else {
            None
        };
        let sacl = if (control_flags & control_flag::SP) != 0
            && off_sacl != 0
            && off_sacl < b.len()
        {
            Some(Acl::parse(&b[off_sacl..])?)
        } else {
            None
        };

        Ok(Self {
            revision,
            control_flags,
            owner,
            group,
            dacl,
            sacl,
        })
    }

    /// True if the DACL is protected from inheritance (PD flag set).
    /// GUI uses this to show "DACL Protected: yes".
    pub fn is_dacl_protected(&self) -> bool {
        self.control_flags & control_flag::PD != 0
    }
}

fn read_sid_at(b: &[u8], off: usize) -> Result<Sid> {
    if off + 8 > b.len() {
        return Err(ParseError::Malformed {
            what: "SD",
            detail: "SID offset beyond buffer".into(),
            offset: off as u64,
        });
    }
    let sub_count = b[off + 1] as usize;
    let need = 8 + sub_count * 4;
    if off + need > b.len() {
        return Err(ParseError::Malformed {
            what: "SD",
            detail: "SID body beyond buffer".into(),
            offset: off as u64,
        });
    }
    Sid::from_bytes(&b[off..off + need])
}
