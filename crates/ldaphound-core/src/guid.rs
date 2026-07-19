//! Windows GUID / UUID.
//!
//! Format per MS-DTYP §2.3.2.3. See `docs/snapshot-format.md` §6.
//!
//! GUIDs are **mixed-endian**: the first three fields (Data1 u32, Data2 u16,
//! Data3 u16) are little-endian, the trailing 8 bytes (Data4) are read in
//! natural byte order. The string form is uppercase hex.

use crate::error::{ParseError, Result};
use std::fmt;

/// 16-byte GUID. Owned, `Send + Sync`, hashable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid([u8; 16]);

impl Guid {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(ParseError::Malformed {
                what: "GUID",
                detail: format!("need 16 bytes, got {}", b.len()),
                offset: 0,
            });
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&b[..16]);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Canonical uppercase string: `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
    /// First three groups use mixed-endian interpretation (Data1/2/3 reversed
    /// to big-endian for display); Data4 stays in stored order.
    pub fn to_string(&self) -> String {
        // Data1 (4 bytes LE) -> u32 -> display big-endian
        let d1 = u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]);
        let d2 = u16::from_le_bytes([self.0[4], self.0[5]]);
        let d3 = u16::from_le_bytes([self.0[6], self.0[7]]);
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            d1, d2, d3,
            self.0[8], self.0[9],
            self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15],
        )
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({})", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_spec_sample() {
        // From spec §6: bytes -> 9B026DA6-0D3C-465C-8BEE-5199D7165CBA
        let bytes = [
            0xA6, 0x6D, 0x02, 0x9B, 0x3C, 0x0D, 0x5C, 0x46,
            0x8B, 0xEE, 0x51, 0x99, 0xD7, 0x16, 0x5C, 0xBA,
        ];
        let guid = Guid::from_bytes(&bytes).unwrap();
        assert_eq!(guid.to_string(), "9B026DA6-0D3C-465C-8BEE-5199D7165CBA");
    }

    #[test]
    fn parses_0718_schema_guid() {
        // From 0718.dat Property[0] (accountExpires) schemaIDGUID:
        // bytes 21 121 150 191 230 13 208 17 162 133 0 170 0 48 73 226
        // -> BF967915-0DE6-11D0-A285-00AA003049E2
        let bytes = [
            0x15, 0x79, 0x96, 0xBF, 0xE6, 0x0D, 0xD0, 0x11,
            0xA2, 0x85, 0x00, 0xAA, 0x00, 0x30, 0x49, 0xE2,
        ];
        let guid = Guid::from_bytes(&bytes).unwrap();
        assert_eq!(guid.to_string(), "BF967915-0DE6-11D0-A285-00AA003049E2");
    }

    #[test]
    fn zero_guid() {
        let bytes = [0u8; 16];
        let guid = Guid::from_bytes(&bytes).unwrap();
        assert_eq!(guid.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn rejects_short_input() {
        assert!(Guid::from_bytes(&[0; 15]).is_err());
    }
}
