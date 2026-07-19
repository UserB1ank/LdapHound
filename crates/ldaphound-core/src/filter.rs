//! Object filtering and lookup.
//!
//! Two responsibilities:
//! - [`resolve_object`]: turn a user query (index / DN / SID string) into a
//!   snapshot object index. Used by the CLI `--object` flag.
//! - [`ObjectType`] + [`Filter`]: coarse LDAP type filtering and substring
//!   matching on DN / name. Reserved for the CLI `--type` / `--filter` flags
//!   and the GUI filter box.

use crate::snapshot::{Object, Snapshot};
use crate::Sid;

/// Resolve a user-supplied object query to a snapshot index.
///
/// Accepted forms (tried in order):
/// - Numeric index into `snapshot.objects` (e.g. `"42"`)
/// - SID string (e.g. `"S-1-5-21-...-519"`)
/// - Distinguished Name (case-insensitive, e.g.
///   `"CN=Administrator,CN=Users,DC=..."`)
///
/// Returns `None` if no object matches.
pub fn resolve_object(snap: &Snapshot, q: &str) -> Option<usize> {
    // 1. Numeric index.
    if let Ok(i) = q.parse::<usize>() {
        return snap.objects.get(i).map(|_| i);
    }
    // 2. SID.
    if let Ok(sid) = q.parse::<Sid>() {
        for (i, o) in snap.objects.iter().enumerate() {
            if o.object_sid().map(|s| s == sid).unwrap_or(false) {
                return Some(i);
            }
        }
    }
    // 3. DN (case-insensitive).
    let lower = q.to_ascii_lowercase();
    for (i, o) in snap.objects.iter().enumerate() {
        if o.dn().map(|d| d.eq_ignore_ascii_case(&lower)).unwrap_or(false) {
            return Some(i);
        }
    }
    None
}

/// Coarse AD object type, derived from `objectClass`. Used by the CLI
/// `--type` flag and the GUI type filter.
///
/// TODO: not yet wired into `Object`; this is the reserved shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    User,
    Group,
    Computer,
    Domain,
    Ou,
    Container,
    Gpo,
    /// Anything not in the list above (schema objects, DNS zones, ...).
    Other,
}

impl ObjectType {
    /// Lowercase name for display and CLI matching.
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectType::User => "user",
            ObjectType::Group => "group",
            ObjectType::Computer => "computer",
            ObjectType::Domain => "domain",
            ObjectType::Ou => "ou",
            ObjectType::Container => "container",
            ObjectType::Gpo => "gpo",
            ObjectType::Other => "other",
        }
    }

    /// Parse from a CLI string (case-insensitive). Returns `None` on
    /// unknown input so the caller can produce a friendly error.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "user" => Some(Self::User),
            "group" => Some(Self::Group),
            "computer" => Some(Self::Computer),
            "domain" => Some(Self::Domain),
            "ou" | "organizationalunit" => Some(Self::Ou),
            "container" => Some(Self::Container),
            "gpo" | "grouppolicycontainer" => Some(Self::Gpo),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// A composed filter: type allow-list AND substring match on DN / name.
///
/// TODO: not yet applied anywhere; the CLI parses the flags but currently
/// only emits a warning. This struct is the reserved shape so the wiring
/// is straightforward once [`ObjectType`] is derived on `Object`.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// When non-empty, an object passes only if its type is in this list.
    /// Empty means "any type".
    pub types: Vec<ObjectType>,
    /// When set, case-insensitive substring that must appear in the DN or
    /// display name. `None` means "any name".
    pub name_contains: Option<String>,
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a type to the allow-list.
    pub fn with_type(mut self, t: ObjectType) -> Self {
        self.types.push(t);
        self
    }

    /// Set the substring filter.
    pub fn with_name_contains(mut self, s: impl Into<String>) -> Self {
        self.name_contains = Some(s.into());
        self
    }

    /// True if this filter is trivially passing (no constraints).
    pub fn is_empty(&self) -> bool {
        self.types.is_empty() && self.name_contains.is_none()
    }

    /// True if the object passes both the type allow-list and the substring
    /// constraint. An empty filter matches everything.
    pub fn matches(&self, obj: &Object) -> bool {
        if !self.types.is_empty() && !self.types.contains(&obj.object_type()) {
            return false;
        }
        if let Some(needle) = &self.name_contains {
            let needle = needle.to_ascii_lowercase();
            let dn = obj.dn().unwrap_or("").to_ascii_lowercase();
            let name = obj.display_name().to_ascii_lowercase();
            if !dn.contains(&needle) && !name.contains(&needle) {
                return false;
            }
        }
        true
    }
}
