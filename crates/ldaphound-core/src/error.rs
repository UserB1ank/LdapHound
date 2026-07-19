//! Error types for snapshot parsing.
//!
//! Errors carry context (current file offset + human description) so users
//! can locate which object/attribute triggered the failure.

use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    /// I/O failure (file not readable, mmap failed, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Not an ADExplorer snapshot (bad signature at offset 0).
    #[error("not an ADExplorer snapshot: bad signature {signature:?}")]
    BadSignature { signature: [u8; 10] },

    /// Read past end of file / mapped buffer.
    #[error("unexpected end of data at offset 0x{offset:x}: need {needed} more bytes")]
    UnexpectedEof { offset: u64, needed: usize },

    /// Offset arithmetic went out of bounds (negative attrOffset underflow etc.).
    #[error("offset out of bounds: {what} (offset=0x{offset:x}, len=0x{len:x})")]
    OutOfBounds {
        what: &'static str,
        offset: u64,
        len: u64,
    },

    /// Unknown/unhandled ads_type during attribute parsing.
    #[error("unhandled ads_type {ads_type} on attribute {attr:?} at offset 0x{offset:x}")]
    UnhandledAdsType {
        ads_type: u32,
        attr: String,
        offset: u64,
    },

    /// Malformed SID / GUID / SecurityDescriptor.
    #[error("malformed {what}: {detail} at offset 0x{offset:x}")]
    Malformed {
        what: &'static str,
        detail: String,
        offset: u64,
    },
}

pub type Result<T> = std::result::Result<T, ParseError>;
