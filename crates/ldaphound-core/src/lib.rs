//! LdapHound core library — parser for ADExplorer `.dat` snapshot files
//! and LDIF (ldapsearch result) imports.
//!
//! See `docs/snapshot-format.md` for the authoritative `.dat` format
//! specification. All public types are `Send + Sync` so they can be passed
//! across threads (required by the GUI's async task layer).

pub mod ai;
pub mod dump;
pub mod error;
pub mod filter;
pub mod graph;
pub mod guid;
pub mod ldif;
pub mod le_reader;
pub mod security;
pub mod sid;
pub mod snapshot;
pub mod tree;

pub use error::{ParseError, Result as ParseErrorResult};
pub use graph::{GraphEdge, GraphNode, GraphSummary, LdapGraph, RelationKind};
pub use guid::Guid;
pub use security::{AccessMask, Ace, AceFlags, AceType, Acl, SecurityDescriptor};
pub use sid::Sid;
pub use snapshot::{Header, Object, Property, Snapshot};
pub use tree::{Tree, TreeNode};
