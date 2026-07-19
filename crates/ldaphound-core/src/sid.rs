//! Windows SID (Security Identifier).
//!
//! Format per MS-DTYP §2.4.2. See `docs/snapshot-format.md` §5.
//!
//! NOTE: `IdentifierAuthority` is **big-endian** (6 bytes), unlike the rest
//! of the snapshot. This is the single most common SID-parsing bug.

use crate::error::{ParseError, Result};
use std::fmt;
use std::str::FromStr;

/// A Windows SID. Owned, `Send + Sync`, hashable for use as HashMap key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    revision: u8,
    authority: u64,
    sub_authorities: Vec<u32>,
}

impl Sid {
    /// Parse a SID from its binary form. Input must be at least
    /// `8 + 4*sub_authority_count` bytes long.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 8 {
            return Err(ParseError::Malformed {
                what: "SID",
                detail: format!("need >=8 bytes, got {}", b.len()),
                offset: 0,
            });
        }
        let revision = b[0];
        let sub_count = b[1] as usize;
        let need = 8 + sub_count * 4;
        if b.len() < need {
            return Err(ParseError::Malformed {
                what: "SID",
                detail: format!("need {need} bytes for {sub_count} sub-authorities, got {}", b.len()),
                offset: 0,
            });
        }
        // IdentifierAuthority is big-endian (6 bytes).
        let authority = u64::from_be_bytes([
            0, 0, b[2], b[3], b[4], b[5], b[6], b[7],
        ]);
        let mut sub_authorities = Vec::with_capacity(sub_count);
        for i in 0..sub_count {
            let off = 8 + i * 4;
            sub_authorities.push(u32::from_le_bytes([
                b[off], b[off + 1], b[off + 2], b[off + 3],
            ]));
        }
        Ok(Self { revision, authority, sub_authorities })
    }

    /// Canonical string form: `S-<rev>-<auth>-<sub0>-<sub1>...`
    pub fn to_string(&self) -> String {
        let mut s = format!("S-{}-{}", self.revision, self.authority);
        for sa in &self.sub_authorities {
            s.push('-');
            s.push_str(&sa.to_string());
        }
        s
    }

    pub fn revision(&self) -> u8 { self.revision }
    pub fn authority(&self) -> u64 { self.authority }
    pub fn sub_authorities(&self) -> &[u32] { &self.sub_authorities }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({})", self.to_string())
    }
}

impl FromStr for Sid {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts[0] != "S" {
            return Err(ParseError::Malformed {
                what: "SID",
                detail: "expected S-...-...".into(),
                offset: 0,
            });
        }
        let revision: u8 = parts[1].parse().map_err(|_| ParseError::Malformed {
            what: "SID", detail: "bad revision".into(), offset: 0,
        })?;
        let authority: u64 = parts[2].parse().map_err(|_| ParseError::Malformed {
            what: "SID", detail: "bad authority".into(), offset: 0,
        })?;
        let mut sub_authorities = Vec::with_capacity(parts.len() - 3);
        for p in &parts[3..] {
            sub_authorities.push(p.parse().map_err(|_| ParseError::Malformed {
                what: "SID", detail: "bad sub-authority".into(), offset: 0,
            })?);
        }
        Ok(Self { revision, authority, sub_authorities })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_wellknown_sid() {
        // S-1-5-32-544 (Administrators)
        let bytes = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
        let sid = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-32-544");
        assert_eq!(sid.revision(), 1);
        assert_eq!(sid.authority(), 5);
        assert_eq!(sid.sub_authorities(), &[32, 544]);
    }

    #[test]
    fn parses_domain_sid() {
        // S-1-5-21-1935163693-1572912069-975596842-1104 (from spec §5)
        let bytes = [
            1, 5, 0, 0, 0, 0, 0, 5,
            21, 0, 0, 0,
            45, 65, 88, 115,
            197, 187, 192, 93,
            42, 109, 38, 58,
            80, 4, 0, 0,
        ];
        let sid = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-21-1935163693-1572912069-975596842-1104");
    }

    #[test]
    fn parses_0718_owner_sid() {
        // Real owner SID from 0718.dat first object's nTSecurityDescriptor:
        // S-1-5-21-2502726253-3859040611-225969357-518
        let bytes = [
            1, 5, 0, 0, 0, 0, 0, 5,
            21, 0, 0, 0,
            0x6D, 0x92, 0x2C, 0x95,   // 2502726253
            0x63, 0x49, 0x04, 0xE6,   // 3859040611
            0xCD, 0x04, 0x78, 0x0D,   // 225969357
            0x06, 0x02, 0x00, 0x00,   // 518
        ];
        let sid = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-21-2502726253-3859040611-225969357-518");
    }

    #[test]
    fn roundtrip_string_parse() {
        let s = "S-1-5-21-1935163693-1572912069-975596842-1104";
        let sid: Sid = s.parse().unwrap();
        assert_eq!(sid.to_string(), s);
    }

    #[test]
    fn rejects_truncated() {
        let bytes = [1, 5, 0, 0]; // sub_authority_count=5 but no sub-authorities
        assert!(Sid::from_bytes(&bytes).is_err());
    }
}
