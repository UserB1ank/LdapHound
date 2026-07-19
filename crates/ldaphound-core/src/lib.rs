//! LdapHound core library — parser for ADExplorer `.dat` snapshot files.
//!
//! See `docs/snapshot-format.md` for the authoritative format specification.
//! All public types are `Send + Sync` so they can be passed across threads
//! (required by the GUI's async task layer).

pub mod dump;
pub mod error;
pub mod filter;
pub mod guid;
pub mod le_reader;
pub mod security;
pub mod sid;
pub mod snapshot;

pub use error::{ParseError, Result as ParseErrorResult};
pub use guid::Guid;
pub use security::{AccessMask, Ace, AceFlags, AceType, Acl, SecurityDescriptor};
pub use sid::Sid;
pub use snapshot::{Header, Object, Property, Snapshot};
