//! Object filtering and lookup.
//!
//! Three responsibilities:
//! - [`resolve_object`]: turn a user query (index / DN / SID string) into a
//!   snapshot object index. Used by the CLI `--object` flag.
//! - [`ObjectType`] + [`Filter`]: coarse LDAP type + substring filter.
//! - [`LdapFilter`]: RFC 4515 §3-style search filter (`(&...)`, `(|...)`,
//!   `(attr=value)`, `(attr>=value)`, `(attr=pre*fix)`, `(attr=*)`).
//!
//! `LdapFilter` powers the CLI `--filter` flag and lets users type real LDAP
//! queries like `(&(objectCategory=person)(objectClass=user))` or
//! `(sAMAccountName=j*)`. The legacy substring `Filter` is kept for the GUI
//! filter box, which prefers a simpler UX.

use crate::snapshot::{AttributeValue, Object, Snapshot};
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
    if let Ok(i) = q.parse::<usize>() {
        return snap.objects.get(i).map(|_| i);
    }
    if let Ok(sid) = q.parse::<Sid>() {
        for (i, o) in snap.objects.iter().enumerate() {
            if o.object_sid().map(|s| s == sid).unwrap_or(false) {
                return Some(i);
            }
        }
    }
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

/// Simple type + substring filter used by the GUI filter box.
/// For full LDAP expression matching see [`LdapFilter`].
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// When non-empty, an object passes only if its type is in this list.
    pub types: Vec<ObjectType>,
    /// When set, case-insensitive substring that must appear in the DN or
    /// display name.
    pub name_contains: Option<String>,
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_type(mut self, t: ObjectType) -> Self {
        self.types.push(t);
        self
    }
    pub fn with_name_contains(mut self, s: impl Into<String>) -> Self {
        self.name_contains = Some(s.into());
        self
    }
    pub fn is_empty(&self) -> bool {
        self.types.is_empty() && self.name_contains.is_none()
    }
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

// ---------------------------------------------------------------------------
// RFC 4515 / RFC 2254 search filter
// ---------------------------------------------------------------------------

/// Parsed LDAP search filter as an AST. Implements a useful subset of
/// RFC 4515 §3:
/// - `(&f1 f2 ...)` / `(|f1 f2 ...)` / `(!f)`
/// - `(attr=value)` exact match (case-insensitive on strings, numeric on
///   integers)
/// - `(attr>=value)` / `(attr<=value)` ordinal (integers, strings compared
///   lexically)
/// - `(attr~=value)` approximation — treated as case-insensitive contains
/// - `(attr=pre*fix)` substring with one or more `*` wildcards
/// - `(attr=*)` presence
///
/// Extensions not implemented: raw `\\hex` escapes (rare in CLI use),
/// `extensible-match` `(attr:=value)`.
#[derive(Debug, Clone)]
pub enum LdapFilter {
    /// All of the children must match.
    And(Vec<LdapFilter>),
    /// At least one child must match.
    Or(Vec<LdapFilter>),
    /// The child must NOT match.
    Not(Box<LdapFilter>),
    /// `attr = value`. For multi-valued attributes, any value matching passes.
    Equality { attr: String, value: String },
    /// `attr >= value`. Numeric for integer attrs, lexical otherwise.
    GreaterOrEqual { attr: String, value: String },
    /// `attr <= value`.
    LessOrEqual { attr: String, value: String },
    /// `attr ~= value`. Treated as case-insensitive substring match.
    Approx { attr: String, value: String },
    /// `attr = a*b*c` — substring match with N wildcards. The `parts` are
    /// the literals between wildcards; `parts[0]` is a prefix anchor and
    /// `parts.last()` is a suffix anchor (empty string means "no anchor").
    Substrings { attr: String, parts: Vec<String> },
    /// `attr = *` — the attribute is present (has at least one value).
    Present { attr: String },
}

impl LdapFilter {
    /// Parse a filter string. The outermost parentheses are required: e.g.
    /// `(objectClass=user)` or `(&(a=b)(c=d))`.
    pub fn parse(input: &str) -> Result<Self, FilterError> {
        let mut p = Parser::new(input);
        let f = p.filter()?;
        p.expect_end()?;
        Ok(f)
    }

    /// True if the object satisfies this filter.
    pub fn matches(&self, obj: &Object) -> bool {
        match self {
            LdapFilter::And(children) => children.iter().all(|c| c.matches(obj)),
            LdapFilter::Or(children) => children.iter().any(|c| c.matches(obj)),
            LdapFilter::Not(c) => !c.matches(obj),
            LdapFilter::Equality { attr, value } => {
                match_attr_values(obj, attr, |v| attr_value_eq(attr, v, value))
            }
            LdapFilter::Approx { attr, value } => {
                let lower = value.to_ascii_lowercase();
                match_attr_values(obj, attr, |v| {
                    v.to_ascii_lowercase().contains(&lower)
                })
            }
            LdapFilter::GreaterOrEqual { attr, value } => {
                match_attr_values(obj, attr, |v| compare_ge(v, value))
            }
            LdapFilter::LessOrEqual { attr, value } => {
                match_attr_values(obj, attr, |v| compare_le(v, value))
            }
            LdapFilter::Substrings { attr, parts } => {
                match_attr_values(obj, attr, |v| substrings_match(v, parts))
            }
            LdapFilter::Present { attr } => {
                obj.get(attr).map(|a| !a.values.is_empty()).unwrap_or(false)
            }
        }
    }
}

/// Human-readable filter-parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("missing opening '(' at position {0}")]
    ExpectedOpen(usize),
    #[error("missing closing ')' at position {0}")]
    ExpectedClose(usize),
    #[error("missing operator in assertion at position {0}")]
    ExpectedOperator(usize),
    #[error("empty attribute name at position {0}")]
    EmptyAttr(usize),
    #[error("unrecognized filter operator '{0}'")]
    UnknownOperator(String),
    #[error("trailing input after filter: {0:?}")]
    Trailing(String),
}

/// Compare a stringified attribute value against an equality assertion.
///
/// Special case: `objectCategory` is stored as a DN
/// (`CN=Person,CN=Schema,...`) but AD tooling conventionally matches it
/// against the bare common name (`Person` or `person`). When the asserted
/// value is not itself a DN, we compare against the first RDN component.
fn attr_value_eq(attr: &str, actual: &str, asserted: &str) -> bool {
    // Numeric fast path (e.g. userAccountControl=512).
    if let (Ok(a), Ok(b)) = (actual.parse::<i64>(), asserted.parse::<i64>()) {
        return a == b;
    }
    if actual.eq_ignore_ascii_case(asserted) {
        return true;
    }
    // objectCategory DN-vs-CN shortcut.
    if attr.eq_ignore_ascii_case("objectCategory") && !asserted.contains('=') {
        if let Some(cn) = actual.split(',').next() {
            if let Some(rest) = cn.strip_prefix("CN=").or_else(|| cn.strip_prefix("cn=")) {
                return rest.eq_ignore_ascii_case(asserted);
            }
        }
    }
    false
}

/// Plain case-insensitive / numeric equality, no special-casing.
#[allow(dead_code)]
fn value_eq(actual: &str, asserted: &str) -> bool {
    if let (Ok(a), Ok(b)) = (actual.parse::<i64>(), asserted.parse::<i64>()) {
        return a == b;
    }
    actual.eq_ignore_ascii_case(asserted)
}

/// `actual >= asserted`. Numeric when both parse as integers, else lexical.
fn compare_ge(actual: &str, asserted: &str) -> bool {
    if let (Ok(a), Ok(b)) = (actual.parse::<i64>(), asserted.parse::<i64>()) {
        return a >= b;
    }
    actual >= asserted
}
fn compare_le(actual: &str, asserted: &str) -> bool {
    if let (Ok(a), Ok(b)) = (actual.parse::<i64>(), asserted.parse::<i64>()) {
        return a <= b;
    }
    actual <= asserted
}

/// `value` against a `pre*mid*suf` pattern. Empty first/last part means the
/// pattern is unanchored on that side.
fn substrings_match(value: &str, parts: &[String]) -> bool {
    if parts.is_empty() {
        return false;
    }
    let value_lower = value.to_ascii_lowercase();
    let last_is_empty = parts.last().map(String::is_empty).unwrap_or(false);
    let non_empty: Vec<&String> = parts.iter().filter(|p| !p.is_empty()).collect();

    let mut cursor = 0usize;
    for (idx, part) in non_empty.iter().enumerate() {
        let part = part.to_ascii_lowercase();
        if idx == 0 && !parts[0].is_empty() {
            // First part of the original `parts` is a prefix anchor.
            if !value_lower[cursor..].starts_with(&part) {
                return false;
            }
            cursor += part.len();
        } else if idx == non_empty.len() - 1 && !last_is_empty {
            // The original pattern's last literal (suffix anchor).
            if !value_lower.ends_with(&part) || cursor + part.len() > value_lower.len() {
                return false;
            }
            cursor = value_lower.len();
        } else {
            // Middle literal — find anywhere after the cursor.
            match value_lower[cursor..].find(&part) {
                Some(pos) => cursor += pos + part.len(),
                None => return false,
            }
        }
    }
    let _ = cursor; // cursor only used inside the loop
    true
}

/// Iterate the string form of every value of `attr` and return true if any
/// value's predicate passes. Non-string values are stringified via their
/// Display form; octet / SD blobs are skipped (callers should use a typed
/// comparison for those).
fn match_attr_values<P: Fn(&str) -> bool>(obj: &Object, attr: &str, pred: P) -> bool {
    let Some(attr) = obj.get(attr) else { return false };
    for v in &attr.values {
        let owned;
        let s: &str = match v {
            AttributeValue::String(s) => s.as_str(),
            AttributeValue::Integer(i) => {
                owned = i.to_string();
                owned.as_str()
            }
            AttributeValue::LargeInteger(i) => {
                owned = i.to_string();
                owned.as_str()
            }
            AttributeValue::Boolean(b) => {
                owned = b.to_string();
                owned.as_str()
            }
            AttributeValue::UtcTime(t) => {
                owned = t.to_string();
                owned.as_str()
            }
            AttributeValue::OctetString(_) | AttributeValue::NtSecurityDescriptor(_) => {
                continue;
            }
        };
        if pred(s) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Recursive-descent parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// Which compound operator we're parsing inside `(...)`.
enum CompoundKind {
    And,
    Or,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect_end(self) -> Result<(), FilterError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(FilterError::Trailing(
                String::from_utf8_lossy(&self.bytes[self.pos..]).into_owned(),
            ))
        }
    }

    /// Parse one filter, including the outer `(...)`.
    fn filter(&mut self) -> Result<LdapFilter, FilterError> {
        if self.peek() != Some(b'(') {
            return Err(FilterError::ExpectedOpen(self.pos));
        }
        self.pos += 1; // consume '('

        // Compound?
        let f = match self.peek() {
            Some(b'&') => self.compound(CompoundKind::And)?,
            Some(b'|') => self.compound(CompoundKind::Or)?,
            Some(b'!') => self.not()?,
            _ => self.assertion()?,
        };
        if self.peek() != Some(b')') {
            return Err(FilterError::ExpectedClose(self.pos));
        }
        self.pos += 1;
        Ok(f)
    }

    fn compound(&mut self, kind: CompoundKind) -> Result<LdapFilter, FilterError> {
        self.pos += 1; // consume '&'|'|'
        let mut children = Vec::new();
        while self.peek() == Some(b'(') {
            children.push(self.filter()?);
        }
        Ok(match kind {
            CompoundKind::And => LdapFilter::And(children),
            CompoundKind::Or => LdapFilter::Or(children),
        })
    }

    fn not(&mut self) -> Result<LdapFilter, FilterError> {
        self.pos += 1; // consume '!'
        let inner = self.filter()?;
        Ok(LdapFilter::Not(Box::new(inner)))
    }

    /// Parse `attr op value` until the closing ')`. The caller consumes ')'.
    fn assertion(&mut self) -> Result<LdapFilter, FilterError> {
        let attr = self.read_attr()?;
        // Operator: '=', '>=', '<=', '~='
        let op_start = self.pos;
        let c = self.peek().ok_or(FilterError::ExpectedOperator(self.pos))?;
        let op = match c {
            b'=' => {
                self.pos += 1;
                "="
            }
            b'>' => {
                self.pos += 1;
                if self.peek() == Some(b'=') {
                    self.pos += 1;
                    ">="
                } else {
                    return Err(FilterError::UnknownOperator(">".into()));
                }
            }
            b'<' => {
                self.pos += 1;
                if self.peek() == Some(b'=') {
                    self.pos += 1;
                    "<="
                } else {
                    return Err(FilterError::UnknownOperator("<".into()));
                }
            }
            b'~' => {
                self.pos += 1;
                if self.peek() == Some(b'=') {
                    self.pos += 1;
                    "~="
                } else {
                    return Err(FilterError::UnknownOperator("~".into()));
                }
            }
            _ => return Err(FilterError::ExpectedOperator(op_start)),
        };
        // Value extends until ')'. No unescaping for now (CLI use).
        let value_end = self.bytes[self.pos..]
            .iter()
            .position(|&b| b == b')')
            .map(|p| self.pos + p)
            .ok_or(FilterError::ExpectedClose(self.pos))?;
        let value = String::from_utf8_lossy(&self.bytes[self.pos..value_end]).into_owned();
        self.pos = value_end;

        // Build the filter node, handling `*` (presence / substrings).
        Ok(build_assertion(&attr, op, &value))
    }

    fn read_attr(&mut self) -> Result<String, FilterError> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'=' || b == b'>' || b == b'<' || b == b'~' || b == b')' {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            return Err(FilterError::EmptyAttr(start));
        }
        Ok(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned())
    }
}

/// Turn `(attr OP value)` into an [`LdapFilter`], expanding `*` wildcards.
fn build_assertion(attr: &str, op: &str, value: &str) -> LdapFilter {
    if op == "=" {
        // Presence: `(attr=*)`
        if value == "*" {
            return LdapFilter::Present { attr: attr.to_string() };
        }
        // Substrings: contains at least one `*` and at least one literal.
        if value.contains('*') {
            let parts: Vec<String> = value.split('*').map(|s| s.to_string()).collect();
            return LdapFilter::Substrings {
                attr: attr.to_string(),
                parts,
            };
        }
        return LdapFilter::Equality {
            attr: attr.to_string(),
            value: value.to_string(),
        };
    }
    let (attr, value) = (attr.to_string(), value.to_string());
    match op {
        ">=" => LdapFilter::GreaterOrEqual { attr, value },
        "<=" => LdapFilter::LessOrEqual { attr, value },
        "~=" => LdapFilter::Approx { attr, value },
        _ => unreachable!("build_assertion: unexpected op {op}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Attribute;

    fn s(v: &str) -> AttributeValue {
        AttributeValue::String(v.into())
    }

    /// Minimal hand-built object for filter tests. Keys are lowercased to
    /// mirror real snapshot parsing.
    fn obj(pairs: &[(&str, Vec<AttributeValue>)]) -> Object {
        let mut attributes = std::collections::HashMap::new();
        for (k, v) in pairs {
            attributes.insert((*k).to_string(), Attribute { values: v.clone() });
        }
        Object { attributes }
    }

    #[test]
    fn parses_simple_equality() {
        let f = LdapFilter::parse("(objectClass=computer)").unwrap();
        match f {
            LdapFilter::Equality { attr, value } => {
                assert_eq!(attr, "objectClass");
                assert_eq!(value, "computer");
            }
            other => panic!("expected Equality, got {other:?}"),
        }
    }

    #[test]
    fn parses_and_nested() {
        let f = LdapFilter::parse("(&(objectCategory=Person)(objectClass=User))").unwrap();
        match f {
            LdapFilter::And(v) => {
                assert_eq!(v.len(), 2);
            }
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn parses_or_not() {
        let _ = LdapFilter::parse("(|(a=b)(c=d))").unwrap();
        let _ = LdapFilter::parse("(!(a=b))").unwrap();
    }

    #[test]
    fn parses_presence() {
        match LdapFilter::parse("(description=*)").unwrap() {
            LdapFilter::Present { attr } => assert_eq!(attr, "description"),
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn parses_substrings() {
        match LdapFilter::parse("(sAMAccountName=j*)").unwrap() {
            LdapFilter::Substrings { attr, parts } => {
                assert_eq!(attr, "sAMAccountName");
                assert_eq!(parts, vec!["j".to_string(), "".to_string()]);
            }
            other => panic!("expected Substrings, got {other:?}"),
        }
        match LdapFilter::parse("(cn=*admin*)").unwrap() {
            LdapFilter::Substrings { parts, .. } => {
                assert_eq!(parts, vec!["".to_string(), "admin".to_string(), "".to_string()]);
            }
            _ => panic!("expected Substrings"),
        }
    }

    #[test]
    fn equality_matches_case_insensitive() {
        let o = obj(&[("objectClass", vec![s("Computer")])]);
        assert!(LdapFilter::parse("(objectClass=computer)").unwrap().matches(&o));
        assert!(LdapFilter::parse("(objectClass=COMPUTER)").unwrap().matches(&o));
        assert!(!LdapFilter::parse("(objectClass=user)").unwrap().matches(&o));
    }

    #[test]
    fn and_matches_all_children() {
        let o = obj(&[
            ("objectCategory", vec![s("Person")]),
            ("objectClass", vec![s("user")]),
        ]);
        let f = LdapFilter::parse("(&(objectCategory=Person)(objectClass=User))").unwrap();
        assert!(f.matches(&o));
        let o2 = obj(&[
            ("objectCategory", vec![s("Person")]),
            ("objectClass", vec![s("computer")]),
        ]);
        assert!(!f.matches(&o2));
    }

    #[test]
    fn substrings_prefix_match() {
        let o = obj(&[("sAMAccountName", vec![s("jdoe")])]);
        assert!(LdapFilter::parse("(sAMAccountName=j*)").unwrap().matches(&o));
        assert!(!LdapFilter::parse("(sAMAccountName=k*)").unwrap().matches(&o));

        let o2 = obj(&[("sAMAccountName", vec![s("admin")])]);
        assert!(LdapFilter::parse("(sAMAccountName=*dmi*)").unwrap().matches(&o2));
    }

    #[test]
    fn presence_match() {
        let o = obj(&[("description", vec![s("x")])]);
        assert!(LdapFilter::parse("(description=*)").unwrap().matches(&o));
        let o2 = obj(&[]);
        assert!(!LdapFilter::parse("(description=*)").unwrap().matches(&o2));
    }

    #[test]
    fn numeric_equality_on_integer_attr() {
        let o = obj(&[(
            "userAccountControl",
            vec![AttributeValue::Integer(512)],
        )]);
        assert!(LdapFilter::parse("(userAccountControl=512)").unwrap().matches(&o));
        assert!(!LdapFilter::parse("(userAccountControl=513)").unwrap().matches(&o));
    }

    #[test]
    fn ge_le_numeric() {
        let o = obj(&[(
            "userAccountControl",
            vec![AttributeValue::Integer(512)],
        )]);
        assert!(LdapFilter::parse("(userAccountControl>=512)").unwrap().matches(&o));
        assert!(LdapFilter::parse("(userAccountControl<=512)").unwrap().matches(&o));
        assert!(!LdapFilter::parse("(userAccountControl>=513)").unwrap().matches(&o));
    }

    #[test]
    fn missing_attr_never_matches() {
        let o = obj(&[]);
        assert!(!LdapFilter::parse("(objectClass=*)").unwrap().matches(&o));
        assert!(!LdapFilter::parse("(objectClass=user)").unwrap().matches(&o));
    }

    #[test]
    fn not_negates() {
        let o = obj(&[("objectClass", vec![s("user")])]);
        assert!(LdapFilter::parse("(!(objectClass=computer))").unwrap().matches(&o));
        assert!(!LdapFilter::parse("(!(objectClass=user))").unwrap().matches(&o));
    }

    #[test]
    fn rejects_missing_parens() {
        assert!(LdapFilter::parse("objectClass=user").is_err());
        assert!(LdapFilter::parse("(objectClass=user").is_err());
        assert!(LdapFilter::parse("(objectClass=user)x").is_err());
    }

    #[test]
    fn objectcategory_dn_vs_bare_cn() {
        // Stored as a DN; assert against the common-name short form.
        let o = obj(&[(
            "objectCategory",
            vec![s("CN=Person,CN=Schema,CN=Configuration,DC=x")],
        )]);
        assert!(LdapFilter::parse("(objectCategory=Person)").unwrap().matches(&o));
        assert!(LdapFilter::parse("(objectCategory=person)").unwrap().matches(&o));
        assert!(!LdapFilter::parse("(objectCategory=Computer)").unwrap().matches(&o));
    }

    #[test]
    fn and_objectcategory_person_and_objectclass_user() {
        // The canonical "find all users" query from the issue.
        let o = obj(&[
            ("objectCategory", vec![s("CN=Person,CN=Schema,CN=Configuration,DC=x")]),
            ("objectClass", vec![s("user")]),
        ]);
        let f = LdapFilter::parse("(&(objectCategory=Person)(objectClass=User))").unwrap();
        assert!(f.matches(&o));

        let computer = obj(&[
            ("objectCategory", vec![s("CN=Computer,CN=Schema,CN=Configuration,DC=x")]),
            ("objectClass", vec![s("computer")]),
        ]);
        assert!(!f.matches(&computer));
    }

    #[test]
    fn objectclass_computer_match() {
        // The "find all computers" query from the issue.
        let o = obj(&[("objectClass", vec![s("top"), s("computer")])]);
        assert!(LdapFilter::parse("(objectClass=computer)").unwrap().matches(&o));
    }

    #[test]
    fn samaccountname_prefix_wildcard() {
        // The "users whose sAMAccountName starts with j" query from the issue.
        let o = obj(&[("sAMAccountName", vec![s("jdoe")])]);
        assert!(LdapFilter::parse("(sAMAccountName=j*)").unwrap().matches(&o));
        let o2 = obj(&[("sAMAccountName", vec![s("admin")])]);
        assert!(!LdapFilter::parse("(sAMAccountName=j*)").unwrap().matches(&o2));
    }
}
