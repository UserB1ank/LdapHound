//! Windows Security Descriptor / ACL / ACE parsing.
//!
//! Used to interpret `nTSecurityDescriptor` byte blobs. Spec §7.
//! One call: [`SecurityDescriptor::from_bytes`] gives you a tree containing
//! Owner/Group SIDs and the DACL/SACL with their ACEs.

pub mod access_mask;
pub mod ace;
pub mod acl;
pub mod descriptor;
pub mod object_type_guid;

pub use access_mask::AccessMask;
pub use ace::{Ace, AceFlags, AceType};
pub use acl::Acl;
pub use descriptor::SecurityDescriptor;
