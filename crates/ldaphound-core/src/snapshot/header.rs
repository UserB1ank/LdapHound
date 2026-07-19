//! Snapshot Header (spec §1).
//!
//! The Python reference mis-attributes the first object's `objSize` field to
//! a header field named `unk0x43a`. We treat the header as exactly 1086
//! bytes (0x000 - 0x43E) and start parsing objects immediately after at
//! offset `0x43E`.

use crate::error::{ParseError, Result};
use crate::le_reader::LeReader;

/// Fixed magic signature at the start of every snapshot.
pub const WIN_AD_SIG: &[u8; 10] = b"win-ad-ob\x00";

/// Absolute offset where the Objects segment begins.
pub const OBJECTS_START: u64 = 0x43E;

/// Snapshot header. Owned; safe to send across threads.
#[derive(Debug, Clone)]
pub struct Header {
    /// Server hostname (e.g. `DC01.garfield.htb`).
    pub server: String,
    /// Snapshot creation time as Windows FILETIME
    /// (100ns ticks since 1601-01-01 UTC).
    pub filetime: u64,
    /// Number of objects in the Objects segment.
    pub num_objects: u32,
    /// Absolute file offset where the Properties segment starts.
    pub metadata_offset: u64,
    /// Absolute file offset where the Treeview segment starts (may be absent).
    pub treeview_offset: u64,
}

impl Header {
    /// Parse the header from the start of the file. Cursor is left at 0x43E.
    pub(crate) fn parse(r: &mut LeReader<'_>) -> Result<Self> {
        r.seek(0)?;

        // 0x000: winAdSig[10]
        let mut sig = [0u8; 10];
        sig.copy_from_slice(r.read_bytes_ref(10)?);
        if &sig != WIN_AD_SIG {
            return Err(ParseError::BadSignature { signature: sig });
        }

        // 0x00A: marker (i32) — ignored, purpose unknown.
        let _marker = r.read_i32()?;
        // 0x00E: filetime (u64)
        let filetime = r.read_u64()?;
        // 0x016: optionalDescription wchar[260] — usually empty, but read
        // exactly to advance cursor to the server field.
        let _opt_desc = r.read_wstring_exact(260)?;
        // 0x21E: server wchar[260]
        let server = r.read_wstring_exact(260)?;

        // 0x426: numObjects
        let num_objects = r.read_u32()?;
        // 0x42A: numAttributes (header copy) — unreliable, ignore. Use the
        // numProperties at metadataOffset instead.
        let _num_attributes = r.read_u32()?;
        // 0x42E: metadataOffset (u64)
        let metadata_offset = r.read_u64()?;
        // 0x436: treeviewOffset (u64)
        let treeview_offset = r.read_u64()?;

        // Cursor is now at 0x43E, exactly where Objects begin.
        Ok(Self {
            server,
            filetime,
            num_objects,
            metadata_offset,
            treeview_offset,
        })
    }

    /// Convert the FILETIME field to a Unix timestamp (seconds since
    /// 1970-01-01 UTC), or `None` if the field is 0 or sentinel max.
    pub fn unix_timestamp(&self) -> Option<i64> {
        if self.filetime == 0 || self.filetime == i64::MAX as u64 {
            return None;
        }
        // 116444736000000000 = FILETIME of 1970-01-01
        Some(((self.filetime as i128 - 116444736000000000) / 10_000_000) as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::le_reader::LeReader;

    /// Embed the first 0x43E bytes of `example/0718.dat` so unit tests don't
    /// require the file at runtime. Built up from verified field values.
    fn sample_header_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; OBJECTS_START as usize];
        // signature
        buf[0..10].copy_from_slice(WIN_AD_SIG);
        // marker i32 @0x00A = 0x10001
        buf[0x00A..0x00E].copy_from_slice(&0x10001_i32.to_le_bytes());
        // filetime u64 @0x00E = 134288560067467310
        let ft: u64 = 134288560067467310;
        buf[0x00E..0x016].copy_from_slice(&ft.to_le_bytes());
        // optionalDescription wchar[260] @0x016 already zeroed
        // server wchar[260] @0x21E = "DC01.garfield.htb"
        let server: Vec<u16> = "DC01.garfield.htb".encode_utf16().collect();
        for (i, cu) in server.iter().enumerate() {
            buf[0x21E + i * 2..0x21E + i * 2 + 2].copy_from_slice(&cu.to_le_bytes());
        }
        // numObjects u32 @0x426 = 3624
        buf[0x426..0x42A].copy_from_slice(&3624u32.to_le_bytes());
        // numAttributes u32 @0x42A (ignored)
        buf[0x42A..0x42E].copy_from_slice(&75553u32.to_le_bytes());
        // metadataOffset u64 @0x42E = 2631269
        buf[0x42E..0x436].copy_from_slice(&2631269u64.to_le_bytes());
        // treeviewOffset u64 @0x436 = 3382092
        buf[0x436..0x43E].copy_from_slice(&3382092u64.to_le_bytes());
        buf
    }

    #[test]
    fn parses_0718_header() {
        let bytes = sample_header_bytes();
        let mut r = LeReader::new(&bytes);
        let h = Header::parse(&mut r).unwrap();
        assert_eq!(h.server, "DC01.garfield.htb");
        assert_eq!(h.filetime, 134288560067467310);
        assert_eq!(h.num_objects, 3624);
        assert_eq!(h.metadata_offset, 2631269);
        assert_eq!(h.treeview_offset, 3382092);
        // Cursor advanced to 0x43E exactly.
        assert_eq!(r.pos(), OBJECTS_START);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut bytes = sample_header_bytes();
        bytes[0] = b'X';
        let mut r = LeReader::new(&bytes);
        match Header::parse(&mut r) {
            Err(ParseError::BadSignature { .. }) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn unix_timestamp_conversion() {
        let bytes = sample_header_bytes();
        let mut r = LeReader::new(&bytes);
        let h = Header::parse(&mut r).unwrap();
        // 134288560067467310 corresponds to ~2026-07-18.
        let ts = h.unix_timestamp().unwrap();
        assert!(ts > 1_700_000_000 && ts < 2_000_000_000);
    }
}
