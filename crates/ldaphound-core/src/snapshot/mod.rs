//! ADExplorer snapshot binary format.
//!
//! Top-level layout (spec §0):
//! ```text
//! 0x000 ┌─────────── Header (fixed 1086 bytes)
//! 0x43E ├─────────── Objects (numObjects × variable)
//!       ├─────────── Properties (at metadataOffset)
//!       ├─────────── Classes
//!       ├─────────── Rights
//!       └─────────── Treeview (optional, may be absent)
//! ```

pub mod attribute;
pub mod header;
pub mod object;
pub mod property;
pub mod snapshot;

pub use attribute::{Attribute, AttributeValue};
pub use header::Header;
pub use object::{MappingEntry, Object};
pub use property::{AdsType, Property};
pub use snapshot::Snapshot;
