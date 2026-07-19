//! LDAP directory tree built from a snapshot's objects.
//!
//! AD objects form a tree indexed by Distinguished Name (DN). Each DN like
//! `CN=foo,OU=bar,DC=x` has a parent DN (`OU=bar,DC=x`) obtained by stripping
//! the first RDN component. We derive the parent–child relationship from DN
//! string manipulation alone — no schema lookup needed.
//!
//! Three naming-context roots:
//! - **Domain NC**: `objectClass=domain` with an `objectSid` (DNS zones also
//!   carry `domain` but have no SID — they hang off the Domain NC as children).
//! - **Configuration NC**: DN starts with `CN=Configuration,`.
//! - **Schema NC**: DN starts with `CN=Schema,CN=Configuration,`.
//!
//! Objects whose parent isn't found in the snapshot (orphan) get bundled under
//! a synthetic "Lost & Found" root so the tree view never drops data.

use std::collections::HashMap;

use crate::snapshot::Snapshot;

/// Built directory tree. Roots are the three naming contexts plus any
/// synthetic groups for orphaned objects.
#[derive(Debug, Clone)]
pub struct Tree {
    pub roots: Vec<TreeNode>,
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Index into `Snapshot.objects`. `usize::MAX` marks a synthetic node
    /// (e.g. "Lost & Found") with no backing object.
    pub obj_idx: usize,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    const SYNTHETIC: usize = usize::MAX;

    fn synthetic() -> Self {
        Self {
            obj_idx: Self::SYNTHETIC,
            children: Vec::new(),
        }
    }
    pub fn is_synthetic(&self) -> bool {
        self.obj_idx == Self::SYNTHETIC
    }
}

impl Snapshot {
    /// Build the directory tree. Children are sorted: container-like objects
    /// (OU / Container / Domain) first, then leaves alphabetically by DN.
    pub fn build_tree(&self) -> Tree {
        // DN (lowercased) -> object index.
        let mut dn_index: HashMap<String, usize> = HashMap::with_capacity(self.objects.len());
        for (i, o) in self.objects.iter().enumerate() {
            if let Some(dn) = o.dn() {
                dn_index.insert(dn.to_ascii_lowercase(), i);
            }
        }

        // children[parent_idx] = list of child obj_idx (unsorted).
        let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
        // Roots by category for stable ordering.
        let mut domain_roots: Vec<usize> = Vec::new();
        let mut config_root: Option<usize> = None;
        let mut schema_root: Option<usize> = None;
        let mut orphans: Vec<usize> = Vec::new();

        for (i, o) in self.objects.iter().enumerate() {
            let Some(dn) = o.dn() else { continue };
            let lower = dn.to_ascii_lowercase();

            // Identify the three NC heads by class, not by DN prefix.
            // (A classSchema literally named "Configuration" would otherwise
            // be mistaken for the Configuration NC head.)
            if o.has_class("dMD") {
                // dMD = schema NC head object.
                schema_root = Some(i);
                continue;
            }
            if o.has_class("configuration") {
                config_root = Some(i);
                continue;
            }
            // Domain NC head: class `domain` and has objectSid.
            if o.has_class("domain") && o.object_sid().is_some() {
                domain_roots.push(i);
                continue;
            }

            // Otherwise look up the parent by DN.
            match parent_dn(&lower).and_then(|p| dn_index.get(&p).copied()) {
                Some(p) => children.entry(p).or_default().push(i),
                None => orphans.push(i),
            }
        }

        // Recursively assemble subtrees.
        let mut roots = Vec::new();
        for &d in &domain_roots {
            roots.push(build_node(d, &children, self));
        }
        if let Some(c) = config_root {
            roots.push(build_node(c, &children, self));
        }
        if let Some(s) = schema_root {
            roots.push(build_node(s, &children, self));
        }
        // DNS zones and anything else without a parent land under a synthetic
        // "Lost & Found" so the user still sees them.
        let mut extra_orphans: Vec<usize> = orphans;
        // DNS zone domains not surfaced as roots go here too.
        for (i, _o) in self.objects.iter().enumerate() {
            if domain_roots.contains(&i) || config_root == Some(i) || schema_root == Some(i) {
                continue;
            }
            // Already parented?
            let parented = children.values().flatten().any(|&c| c == i);
            if !parented && !extra_orphans.contains(&i) {
                extra_orphans.push(i);
            }
        }
        if !extra_orphans.is_empty() {
            let mut node = TreeNode::synthetic();
            for &i in &extra_orphans {
                node.children.push(build_node(i, &children, self));
            }
            sort_children(&mut node.children, self);
            roots.push(node);
        }

        // Stable root ordering: domains, config, schema, lost&found.
        // (Already in this order by construction.)

        Tree { roots }
    }
}

fn build_node(idx: usize, children: &HashMap<usize, Vec<usize>>, snap: &Snapshot) -> TreeNode {
    let mut node = TreeNode {
        obj_idx: idx,
        children: Vec::new(),
    };
    if let Some(list) = children.get(&idx) {
        for &c in list {
            node.children.push(build_node(c, children, snap));
        }
        sort_children(&mut node.children, snap);
    }
    node
}

fn sort_children(nodes: &mut [TreeNode], snap: &Snapshot) {
    nodes.sort_by_key(|n| {
        let obj = &snap.objects[n.obj_idx];
        let is_container = is_container(obj);
        // false (0) sorts before true (1): containers first.
        (!is_container, obj.dn().unwrap_or("").to_ascii_lowercase())
    });
}

fn is_container(o: &crate::Object) -> bool {
    o.has_class("organizationalunit")
        || o.has_class("container")
        || o.has_class("domain")
        || o.has_class("configuration")
}

/// Strip the leading RDN component of a DN, returning the parent DN.
/// `CN=foo,OU=bar,DC=x` -> `ou=bar,dc=x`. Returns `None` if the DN has no
/// comma (already a root). Comma splitting is naive — doesn't handle escaped
/// commas inside RDN values, which are rare in AD DNs.
fn parent_dn(dn_lower: &str) -> Option<String> {
    let comma = dn_lower.find(',')?;
    Some(dn_lower[comma + 1..].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_dn_basic() {
        assert_eq!(
            parent_dn("cn=foo,ou=bar,dc=x").as_deref(),
            Some("ou=bar,dc=x")
        );
        assert_eq!(parent_dn("dc=x").as_deref(), None);
    }
}
