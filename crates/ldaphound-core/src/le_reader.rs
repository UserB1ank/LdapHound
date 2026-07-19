//! Low-level little-endian reader over a byte slice.
//!
//! All snapshot fields are little-endian; this reader tracks the current
//! offset and returns `ParseError::UnexpectedEof` on underflow so callers
//! don't have to plumb `Result` through every trivial `read_u32`.
//!
//! Strings are UTF-16LE. See `docs/snapshot-format.md` §0.

use crate::error::{ParseError, Result};

/// Cursor over a byte slice with offset tracking.
pub struct LeReader<'a> {
    data: &'a [u8],
    pos: u64,
}

impl<'a> LeReader<'a> {
    /// Wrap a byte slice. Cursor starts at offset 0.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current absolute offset.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Total length of the underlying slice.
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    /// Seek to an absolute offset.
    pub fn seek(&mut self, pos: u64) -> Result<()> {
        if pos > self.data.len() as u64 {
            return Err(ParseError::OutOfBounds {
                what: "seek",
                offset: pos,
                len: self.data.len() as u64,
            });
        }
        self.pos = pos;
        Ok(())
    }

    /// Advance the cursor by `n` bytes.
    pub fn skip(&mut self, n: u64) -> Result<()> {
        let new = self.pos.checked_add(n).ok_or(ParseError::OutOfBounds {
            what: "skip overflow",
            offset: self.pos,
            len: self.data.len() as u64,
        })?;
        self.seek(new)
    }

    /// Borrow `n` bytes starting at the cursor and advance.
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let start = self.pos as usize;
        let end = start.checked_add(n).ok_or(ParseError::OutOfBounds {
            what: "take overflow",
            offset: self.pos,
            len: self.data.len() as u64,
        })?;
        if end > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                offset: self.pos,
                needed: n,
            });
        }
        let slice = &self.data[start..end];
        self.pos = end as u64;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_i16(&mut self) -> Result<i16> {
        Ok(self.read_u16()? as i16)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        Ok(self.read_u64()? as i64)
    }

    /// Read a UTF-16LE string prefixed by a u32 byte-length (NOT char count).
    /// The length includes any trailing null terminator; reading stops at the
    /// first `u16 == 0`. See spec §4.2 (`propName`) etc.
    pub fn read_wstring_prefixed(&mut self) -> Result<String> {
        let byte_len = self.read_u32()? as usize;
        self.read_wstring_exact(byte_len / 2)
    }

    /// Read `num_chars` UTF-16 code units (i.e. `num_chars * 2` bytes),
    /// stopping at the first null terminator if present.
    pub fn read_wstring_exact(&mut self, num_chars: usize) -> Result<String> {
        let bytes = self.take(num_chars * 2)?;
        let mut code_units = Vec::with_capacity(num_chars);
        for chunk in bytes.chunks_exact(2) {
            let u = u16::from_le_bytes([chunk[0], chunk[1]]);
            if u == 0 {
                break;
            }
            code_units.push(u);
        }
        Ok(String::from_utf16_lossy(&code_units))
    }

    /// Read a null-terminated UTF-16LE string at the current cursor.
    /// Used for attribute string values (spec §3.4): seek to the value's
    /// offset, then call this. Reads until `u16 == 0`.
    pub fn read_wstring_until_null(&mut self) -> Result<String> {
        let mut code_units = Vec::new();
        loop {
            let b = self.take(2)?;
            let u = u16::from_le_bytes([b[0], b[1]]);
            if u == 0 {
                break;
            }
            code_units.push(u);
        }
        Ok(String::from_utf16_lossy(&code_units))
    }

    /// Read `n` raw bytes (owned copy).
    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        Ok(self.take(n)?.to_vec())
    }

    /// Borrow `n` raw bytes without copying (zero-copy path).
    pub fn read_bytes_ref(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_le_integers() {
        let bytes = [0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00];
        let mut r = LeReader::new(&bytes);
        assert_eq!(r.read_u16().unwrap(), 1);
        assert_eq!(r.read_u16().unwrap(), 2);
        assert_eq!(r.read_u32().unwrap(), 3);
        assert_eq!(r.pos(), 8);
    }

    #[test]
    fn eof_on_underflow() {
        let bytes = [0x01, 0x02];
        let mut r = LeReader::new(&bytes);
        r.read_u32().unwrap_err();
    }

    #[test]
    fn wstring_stops_at_null() {
        // "AB\0X" -> should read "AB" and stop at null
        let bytes = [b'A', 0x00, b'B', 0x00, 0x00, 0x00, b'X', 0x00];
        let mut r = LeReader::new(&bytes);
        let s = r.read_wstring_until_null().unwrap();
        assert_eq!(s, "AB");
        // cursor advanced past the null terminator
        assert_eq!(r.pos(), 6);
    }

    #[test]
    fn wstring_prefixed() {
        // len=4 bytes ("AB"), then garbage
        let bytes = [0x04, 0x00, 0x00, 0x00, b'A', 0x00, b'B', 0x00, 0xFF, 0xFF];
        let mut r = LeReader::new(&bytes);
        let s = r.read_wstring_prefixed().unwrap();
        assert_eq!(s, "AB");
        assert_eq!(r.pos(), 8);
    }

    #[test]
    fn seek_and_skip() {
        let bytes = [0; 16];
        let mut r = LeReader::new(&bytes);
        r.seek(8).unwrap();
        assert_eq!(r.pos(), 8);
        r.skip(4).unwrap();
        assert_eq!(r.pos(), 12);
        assert!(r.seek(100).is_err());
    }
}
