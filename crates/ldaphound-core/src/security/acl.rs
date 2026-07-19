//! Access Control List (ACL). Spec §7.3.

use crate::error::{ParseError, Result};
use crate::security::ace::Ace;

/// An ACL — header + a list of ACEs.
#[derive(Debug, Clone)]
pub struct Acl {
    pub revision: u8,
    pub ace_count: u16,
    pub aces: Vec<Ace>,
}

impl Acl {
    /// Parse an ACL from the given slice. Reads exactly the number of bytes
    /// declared by `AclSize`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(ParseError::Malformed {
                what: "ACL",
                detail: "header < 8 bytes".into(),
                offset: 0,
            });
        }
        let revision = bytes[0];
        // sbz1 at [1] ignored
        let acl_size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let ace_count = u16::from_le_bytes([bytes[4], bytes[5]]);
        // sbz2 at [6..8] ignored
        if acl_size < 8 || bytes.len() < acl_size {
            return Err(ParseError::Malformed {
                what: "ACL",
                detail: format!(
                    "declared size {acl_size} invalid for input {}",
                    bytes.len()
                ),
                offset: 0,
            });
        }
        let mut p = 8;
        let mut aces = Vec::with_capacity(ace_count as usize);
        for _ in 0..ace_count {
            if p >= acl_size {
                break;
            }
            let (ace, consumed) = Ace::parse(&bytes[p..acl_size])?;
            p += consumed;
            aces.push(ace);
        }
        Ok(Self {
            revision,
            ace_count,
            aces,
        })
    }
}
