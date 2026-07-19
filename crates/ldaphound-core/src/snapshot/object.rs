//! Object — one directory entry (user/group/computer/OU/...). Spec §2.
//!
//! Each object is variable-length; its total size is given by the `objSize`
//! field. Within an object a mapping table maps (attr_index → attr_offset)
//! where attr_offset is **signed** and may be negative (shared storage with
//! a previous object — see spec §2.2).

use std::collections::HashMap;

use crate::error::Result;
use crate::guid::Guid;
use crate::le_reader::LeReader;
use crate::sid::Sid;
use crate::snapshot::attribute::{Attribute, AttributeValue};
use crate::snapshot::property::Property;

/// One entry in an object's mapping table.
#[derive(Debug, Clone, Copy)]
pub struct MappingEntry {
    /// Index into the Properties vector.
    pub attr_index: u32,
    /// Signed offset from object start to this attribute's data.
    pub attr_offset: i32,
}

/// A directory object and its parsed attributes.
#[derive(Debug, Clone)]
pub struct Object {
    pub attributes: HashMap<String, Attribute>,
}

impl Object {
    /// Parse one object starting at `obj_start`. After parsing the cursor is
    /// advanced to `obj_start + obj_size` (the start of the next object).
    pub(crate) fn parse(
        r: &mut LeReader<'_>,
        obj_start: u64,
        properties: &[Property],
    ) -> Result<Self> {
        r.seek(obj_start)?;
        let obj_size = r.read_u32()? as u64;
        let table_size = r.read_u32()? as usize;

        // Mapping table: table_size × (u32 attr_index, i32 attr_offset).
        let mut entries = Vec::with_capacity(table_size);
        for _ in 0..table_size {
            let attr_index = r.read_u32()?;
            let attr_offset = r.read_i32()?;
            entries.push(MappingEntry {
                attr_index,
                attr_offset,
            });
        }

        // Parse each attribute by seeking to (obj_start + signed offset).
        let mut attributes = HashMap::with_capacity(table_size);
        for entry in &entries {
            let Some(prop) = properties.get(entry.attr_index as usize) else {
                // attr_index out of range — skip rather than fail the whole
                // snapshot. Logged at debug level in the future.
                continue;
            };
            // Handle the negative-offset shared-storage case (spec §2.2).
            let abs_offset = if entry.attr_offset >= 0 {
                obj_start + entry.attr_offset as u64
            } else {
                obj_start - entry.attr_offset.unsigned_abs() as u64
            };
            r.seek(abs_offset)?;
            let attr = Attribute::parse(r, abs_offset, prop.ads_type)?;
            attributes.insert(prop.name.clone(), attr);
        }

        // Advance cursor to the next object regardless of where parsing
        // ended (attribute reads may leave it anywhere).
        r.seek(obj_start + obj_size)?;

        Ok(Self { attributes })
    }

    /// Get all values for an attribute (case-insensitive lookup on the
    /// attribute name as stored — AD attribute names are already lowercase
    /// by convention in snapshots, but the canonical LDAP name may differ).
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        // Try exact first, then case-insensitive scan.
        if let Some(a) = self.attributes.get(name) {
            return Some(a);
        }
        let lower = name.to_ascii_lowercase();
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&lower))
            .map(|(_, v)| v)
    }

    /// First value of an attribute (most attributes are single-valued).
    pub fn get_first(&self, name: &str) -> Option<&AttributeValue> {
        self.get(name).and_then(|a| a.values.first())
    }

    /// `objectClass` values — the LDAP class hierarchy (e.g. `top, user,
    /// person, organizationalPerson`). Lower-cased for stable comparison.
    pub fn object_classes(&self) -> Vec<String> {
        match self.get("objectClass") {
            Some(a) => a
                .values
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// True if the object has the given class anywhere in its objectClass
    /// hierarchy (case-insensitive).
    pub fn has_class(&self, class: &str) -> bool {
        self.object_classes().iter().any(|c| c.eq_ignore_ascii_case(class))
    }

    /// `distinguishedName` (e.g. `CN=Administrator,CN=Users,DC=...`).
    pub fn dn(&self) -> Option<&str> {
        self.get_first("distinguishedName").and_then(AttributeValue::as_str)
    }

    /// `objectSid` parsed as a [`Sid`]. None if absent or malformed.
    pub fn object_sid(&self) -> Option<Sid> {
        let bytes = self
            .get_first("objectSid")
            .and_then(AttributeValue::as_octet_bytes)?;
        Sid::from_bytes(bytes).ok()
    }

    /// `objectGUID` parsed as a [`Guid`]. None if absent or malformed.
    pub fn object_guid(&self) -> Option<Guid> {
        let bytes = self
            .get_first("objectGUID")
            .and_then(AttributeValue::as_octet_bytes)?;
        Guid::from_bytes(bytes).ok()
    }

    /// Raw `nTSecurityDescriptor` bytes (GUI core data). None if absent.
    pub fn ntsd_bytes(&self) -> Option<&[u8]> {
        self.get_first("nTSecurityDescriptor")
            .and_then(AttributeValue::as_nt_security_descriptor)
    }

    /// Common-name / leaf label (e.g. `Administrator` for
    /// `CN=Administrator,CN=Users,...`). Falls back to the DN if `cn`/`name`
    /// is absent.
    pub fn display_name(&self) -> String {
        if let Some(s) = self.get_first("name").and_then(AttributeValue::as_str) {
            return s.to_string();
        }
        if let Some(s) = self.get_first("cn").and_then(AttributeValue::as_str) {
            return s.to_string();
        }
        if let Some(dn) = self.dn() {
            return dn.to_string();
        }
        "<unknown>".to_string()
    }

    /// Best human-readable login-style identifier. Prefers attributes that
    /// uniquely identify security principals in tooling output:
    /// `sAMAccountName` (e.g. `j.arbuckle`, `DC01$`) → `userPrincipalName`
    /// (e.g. `user@domain`) → [`display_name`]. Used for ACL trustee
    /// rendering so users see a recognizable name instead of just a SID or
    /// DN component.
    pub fn principal_name(&self) -> String {
        if let Some(s) = self.get_first("sAMAccountName").and_then(AttributeValue::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(s) = self.get_first("userPrincipalName").and_then(AttributeValue::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
        self.display_name()
    }

    /// Coarse LDAP type derived from `objectClass`. Mirrors the categories
    /// BloodHound and most AD tooling care about.
    ///
    /// Selection notes:
    /// - `computer` is checked before `user` because computer objects also
    ///   carry `user` in their class hierarchy.
    /// - `domain` matches both real domains and DNS zones (which share the
    ///   `domain` class); callers needing to distinguish should check
    ///   `objectSid` presence — DNS zones have none.
    pub fn object_type(&self) -> crate::filter::ObjectType {
        use crate::filter::ObjectType;
        let classes = self.object_classes();
        if classes.iter().any(|c| c == "computer") {
            return ObjectType::Computer;
        }
        if classes.iter().any(|c| c == "user") {
            return ObjectType::User;
        }
        if classes.iter().any(|c| c == "group") {
            return ObjectType::Group;
        }
        if classes.iter().any(|c| c == "domain") {
            return ObjectType::Domain;
        }
        if classes.iter().any(|c| c == "organizationalunit") {
            return ObjectType::Ou;
        }
        if classes.iter().any(|c| c == "container") {
            return ObjectType::Container;
        }
        if classes.iter().any(|c| c == "grouppolicycontainer") {
            return ObjectType::Gpo;
        }
        ObjectType::Other
    }
}
