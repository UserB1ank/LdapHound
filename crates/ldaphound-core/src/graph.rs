//! Privacy-bounded LDAP relationship graph exposed to analysis clients.
//!
//! The graph deliberately does not retain arbitrary LDAP attributes or raw
//! security descriptors. It keeps identity and security-posture fields,
//! turns membership/management/ACL data into typed edges, and records how
//! many other attributes were omitted. This makes the exact AI-visible data
//! inspectable with `ldaphound-cli --export-ai-graph`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::Serialize;

use crate::security::descriptor::SecurityDescriptor;
use crate::snapshot::{AttributeValue, Object};
use crate::{AceType, Snapshot};

const MAX_ATTRIBUTE_VALUES: usize = 24;
const MAX_ATTRIBUTE_VALUE_CHARS: usize = 512;
const MAX_SEARCH_RESULTS: usize = 100;
const MAX_NEIGHBORS: usize = 200;
const MAX_PATH_DEPTH: usize = 8;
const MAX_PATHS: usize = 10;
const MAX_PATH_STATES: usize = 50_000;

/// A directory object (or an unresolved external identity) in the graph.
#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: usize,
    pub name: String,
    pub object_type: String,
    pub dn: Option<String>,
    pub sid: Option<String>,
    /// Curated, bounded attributes that are useful for security analysis.
    pub attributes: BTreeMap<String, Vec<String>>,
    /// Number of source attributes intentionally withheld from AI/export.
    pub omitted_attribute_count: usize,
    pub external: bool,
}

/// Typed relationship direction is always `source -> target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Contains,
    MemberOf,
    Manages,
    Owns,
    AclAllow,
    AclDeny,
    AllowedToAct,
    DelegatesToService,
    AppliesGpo,
    SidHistoryOf,
}

impl RelationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contains => "contains",
            Self::MemberOf => "member_of",
            Self::Manages => "manages",
            Self::Owns => "owns",
            Self::AclAllow => "acl_allow",
            Self::AclDeny => "acl_deny",
            Self::AllowedToAct => "allowed_to_act",
            Self::DelegatesToService => "delegates_to_service",
            Self::AppliesGpo => "applies_gpo",
            Self::SidHistoryOf => "sid_history_of",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "contains" => Some(Self::Contains),
            "member_of" => Some(Self::MemberOf),
            "manages" => Some(Self::Manages),
            "owns" => Some(Self::Owns),
            "acl_allow" => Some(Self::AclAllow),
            "acl_deny" => Some(Self::AclDeny),
            "allowed_to_act" => Some(Self::AllowedToAct),
            "delegates_to_service" => Some(Self::DelegatesToService),
            "applies_gpo" => Some(Self::AppliesGpo),
            "sid_history_of" => Some(Self::SidHistoryOf),
            _ => None,
        }
    }
}

/// One graph relationship. ACL relationships carry their right and mask.
#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub id: usize,
    pub source: usize,
    pub target: usize,
    pub relation: RelationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_mask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphSummary {
    pub nodes: usize,
    pub directory_nodes: usize,
    pub external_nodes: usize,
    pub edges: usize,
    pub node_types: BTreeMap<String, usize>,
    pub relation_types: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LdapGraph {
    pub schema_version: u32,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(skip)]
    outgoing: Vec<Vec<usize>>,
    #[serde(skip)]
    incoming: Vec<Vec<usize>>,
    #[serde(skip)]
    dn_index: HashMap<String, usize>,
    #[serde(skip)]
    sid_index: HashMap<String, usize>,
    #[serde(skip)]
    external_index: HashMap<String, usize>,
    #[serde(skip)]
    edge_keys: HashSet<String>,
}

impl LdapGraph {
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        let mut graph = Self {
            schema_version: 1,
            nodes: snapshot
                .objects
                .iter()
                .enumerate()
                .map(|(id, object)| graph_node(id, object))
                .collect(),
            edges: Vec::new(),
            outgoing: vec![Vec::new(); snapshot.objects.len()],
            incoming: vec![Vec::new(); snapshot.objects.len()],
            dn_index: HashMap::new(),
            sid_index: HashMap::new(),
            external_index: HashMap::new(),
            edge_keys: HashSet::new(),
        };
        graph.rebuild_identity_indexes();

        for (object_id, object) in snapshot.objects.iter().enumerate() {
            graph.add_containment(object_id, object);
            graph.add_dn_relationships(object_id, object);
            graph.add_primary_group(object_id, object);
            graph.add_security_descriptor_edges(object_id, object);
            graph.add_rbcd_edges(object_id, object);
            graph.add_delegation_edges(object_id, object);
            graph.add_sid_history_edges(object_id, object);
            graph.add_gpo_edges(object_id, object);
        }
        graph
    }

    pub fn summary(&self) -> GraphSummary {
        let mut node_types = BTreeMap::new();
        let mut relation_types = BTreeMap::new();
        for node in &self.nodes {
            *node_types.entry(node.object_type.clone()).or_insert(0) += 1;
        }
        for edge in &self.edges {
            *relation_types
                .entry(edge.relation.as_str().to_string())
                .or_insert(0) += 1;
        }
        let external_nodes = self.nodes.iter().filter(|node| node.external).count();
        GraphSummary {
            nodes: self.nodes.len(),
            directory_nodes: self.nodes.len() - external_nodes,
            external_nodes,
            edges: self.edges.len(),
            node_types,
            relation_types,
        }
    }

    pub fn node(&self, id: usize) -> Option<&GraphNode> {
        self.nodes.get(id)
    }

    pub fn search_nodes(
        &self,
        query: &str,
        object_type: Option<&str>,
        limit: usize,
    ) -> Vec<&GraphNode> {
        let needle = query.to_ascii_lowercase();
        let type_filter = object_type.map(str::to_ascii_lowercase);
        self.nodes
            .iter()
            .filter(|node| {
                type_filter
                    .as_ref()
                    .map(|kind| node.object_type.eq_ignore_ascii_case(kind))
                    .unwrap_or(true)
            })
            .filter(|node| {
                needle.is_empty()
                    || node.name.to_ascii_lowercase().contains(&needle)
                    || node
                        .dn
                        .as_deref()
                        .map(|dn| dn.to_ascii_lowercase().contains(&needle))
                        .unwrap_or(false)
                    || node
                        .sid
                        .as_deref()
                        .map(|sid| sid.to_ascii_lowercase().contains(&needle))
                        .unwrap_or(false)
                    || node.attributes.iter().any(|(name, values)| {
                        name.to_ascii_lowercase().contains(&needle)
                            || values
                                .iter()
                                .any(|value| value.to_ascii_lowercase().contains(&needle))
                    })
            })
            .take(limit.clamp(1, MAX_SEARCH_RESULTS))
            .collect()
    }

    pub fn neighbors(
        &self,
        node_id: usize,
        direction: &str,
        relation: Option<RelationKind>,
        limit: usize,
    ) -> Vec<&GraphEdge> {
        if node_id >= self.nodes.len() {
            return Vec::new();
        }
        let mut ids = Vec::new();
        if matches!(direction, "outgoing" | "both") {
            ids.extend_from_slice(&self.outgoing[node_id]);
        }
        if matches!(direction, "incoming" | "both") {
            ids.extend_from_slice(&self.incoming[node_id]);
        }
        ids.into_iter()
            .filter_map(|id| self.edges.get(id))
            .filter(|edge| relation.map(|kind| edge.relation == kind).unwrap_or(true))
            .take(limit.clamp(1, MAX_NEIGHBORS))
            .collect()
    }

    /// Find short directed paths. `both` is useful for relationship
    /// exploration; `outgoing` follows capability/membership direction.
    pub fn find_paths(
        &self,
        start: usize,
        end: usize,
        direction: &str,
        max_depth: usize,
        max_paths: usize,
    ) -> Vec<Vec<usize>> {
        if start >= self.nodes.len() || end >= self.nodes.len() {
            return Vec::new();
        }
        let max_depth = max_depth.clamp(1, MAX_PATH_DEPTH);
        let max_paths = max_paths.clamp(1, MAX_PATHS);
        let mut queue = VecDeque::from([(start, Vec::<usize>::new(), vec![start])]);
        let mut results = Vec::new();
        let mut states = 0usize;

        while let Some((node, edge_path, node_path)) = queue.pop_front() {
            states += 1;
            if states > MAX_PATH_STATES || results.len() >= max_paths {
                break;
            }
            if edge_path.len() >= max_depth {
                continue;
            }
            let mut edge_ids = Vec::new();
            if matches!(direction, "outgoing" | "both") {
                edge_ids.extend_from_slice(&self.outgoing[node]);
            }
            if matches!(direction, "incoming" | "both") {
                edge_ids.extend_from_slice(&self.incoming[node]);
            }
            for edge_id in edge_ids {
                let edge = &self.edges[edge_id];
                let next = if edge.source == node {
                    edge.target
                } else {
                    edge.source
                };
                if node_path.contains(&next) {
                    continue;
                }
                let mut next_edges = edge_path.clone();
                next_edges.push(edge_id);
                if next == end {
                    results.push(next_edges);
                    if results.len() >= max_paths {
                        break;
                    }
                    continue;
                }
                let mut next_nodes = node_path.clone();
                next_nodes.push(next);
                queue.push_back((next, next_edges, next_nodes));
            }
        }
        results
    }

    pub fn risky_edges(&self, limit: usize) -> Vec<&GraphEdge> {
        self.edges
            .iter()
            .filter(|edge| self.edge_risk_reason(edge).is_some())
            .take(limit.clamp(1, MAX_NEIGHBORS))
            .collect()
    }

    pub fn edge_risk_reason(&self, edge: &GraphEdge) -> Option<&'static str> {
        match edge.relation {
            RelationKind::AllowedToAct => Some("resource-based constrained delegation"),
            RelationKind::DelegatesToService => Some("Kerberos constrained delegation"),
            RelationKind::Owns => Some("object ownership can enable ACL changes"),
            RelationKind::MemberOf if self.is_privileged_group(edge.target) => {
                Some("membership in a privileged group")
            }
            RelationKind::AclAllow => {
                let right = edge.right.as_deref().unwrap_or("");
                if [
                    "GenericAll",
                    "GenericWrite",
                    "WriteDACL",
                    "WriteOwner",
                    "WriteProperty",
                    "ExtendedRight",
                    "DS-Replication-Get-Changes",
                    "DS-Replication-Get-Changes-All",
                ]
                .iter()
                .any(|risk| right.contains(risk))
                {
                    Some("high-impact allowed ACL right")
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn rebuild_identity_indexes(&mut self) {
        for node in &self.nodes {
            if let Some(dn) = &node.dn {
                self.dn_index.insert(normalize_dn(dn), node.id);
            }
            if let Some(sid) = &node.sid {
                self.sid_index.insert(sid.to_ascii_lowercase(), node.id);
            }
        }
    }

    fn add_containment(&mut self, object_id: usize, object: &Object) {
        let Some(dn) = object.dn() else { return };
        let Some(parent) = parent_dn(dn) else { return };
        if let Some(parent_id) = self.dn_index.get(&normalize_dn(&parent)).copied() {
            self.add_edge(
                parent_id,
                object_id,
                RelationKind::Contains,
                None,
                None,
                None,
                None,
            );
        }
    }

    fn add_dn_relationships(&mut self, object_id: usize, object: &Object) {
        for member_dn in string_values(object, "member") {
            let member_id = self.resolve_or_insert_dn(member_dn);
            self.add_edge(
                member_id,
                object_id,
                RelationKind::MemberOf,
                None,
                None,
                None,
                None,
            );
        }
        for group_dn in string_values(object, "memberOf") {
            let group_id = self.resolve_or_insert_dn(group_dn);
            self.add_edge(
                object_id,
                group_id,
                RelationKind::MemberOf,
                None,
                None,
                None,
                None,
            );
        }
        for manager_dn in string_values(object, "manager") {
            let manager_id = self.resolve_or_insert_dn(manager_dn);
            self.add_edge(
                manager_id,
                object_id,
                RelationKind::Manages,
                None,
                None,
                None,
                None,
            );
        }
        for manager_dn in string_values(object, "managedBy") {
            let manager_id = self.resolve_or_insert_dn(manager_dn);
            self.add_edge(
                manager_id,
                object_id,
                RelationKind::Manages,
                None,
                None,
                None,
                None,
            );
        }
    }

    fn add_primary_group(&mut self, object_id: usize, object: &Object) {
        let Some(rid) = first_u32(object, "primaryGroupID") else {
            return;
        };
        let Some(sid) = object.object_sid().map(|sid| sid.to_string()) else {
            return;
        };
        let Some((prefix, _)) = sid.rsplit_once('-') else {
            return;
        };
        let group_sid = format!("{prefix}-{rid}");
        let group_id = self.resolve_or_insert_sid(&group_sid);
        self.add_edge(
            object_id,
            group_id,
            RelationKind::MemberOf,
            None,
            None,
            None,
            Some("primaryGroupID".into()),
        );
    }

    fn add_security_descriptor_edges(&mut self, object_id: usize, object: &Object) {
        let Some(bytes) = object.ntsd_bytes() else {
            return;
        };
        let Ok(sd) = SecurityDescriptor::from_bytes(bytes) else {
            return;
        };
        if let Some(owner) = sd.owner {
            let owner_id = self.resolve_or_insert_sid(&owner.to_string());
            self.add_edge(
                owner_id,
                object_id,
                RelationKind::Owns,
                None,
                None,
                None,
                None,
            );
        }
        if let Some(dacl) = sd.dacl {
            for ace in dacl.aces {
                let Some(trustee) = ace.trustee() else {
                    continue;
                };
                let source = self.resolve_or_insert_sid(&trustee.to_string());
                let relation = match ace.ace_type() {
                    AceType::AccessAllowed | AceType::AccessAllowedObject => RelationKind::AclAllow,
                    AceType::AccessDenied | AceType::AccessDeniedObject => RelationKind::AclDeny,
                    _ => continue,
                };
                self.add_edge(
                    source,
                    object_id,
                    relation,
                    ace.right_name(),
                    Some(ace.is_inherited()),
                    ace.mask().map(|mask| mask.to_string()),
                    None,
                );
            }
        }
    }

    fn add_rbcd_edges(&mut self, object_id: usize, object: &Object) {
        let Some(attribute) = object.get("msDS-AllowedToActOnBehalfOfOtherIdentity") else {
            return;
        };
        for value in &attribute.values {
            let Some(bytes) = value.as_octet_bytes() else {
                continue;
            };
            let Ok(sd) = SecurityDescriptor::from_bytes(bytes) else {
                continue;
            };
            for ace in sd.dacl.into_iter().flat_map(|dacl| dacl.aces) {
                if !ace.ace_type().is_allow() {
                    continue;
                }
                if let Some(trustee) = ace.trustee() {
                    let source = self.resolve_or_insert_sid(&trustee.to_string());
                    self.add_edge(
                        source,
                        object_id,
                        RelationKind::AllowedToAct,
                        ace.right_name(),
                        Some(ace.is_inherited()),
                        ace.mask().map(|mask| mask.to_string()),
                        None,
                    );
                }
            }
        }
    }

    fn add_delegation_edges(&mut self, object_id: usize, object: &Object) {
        for service in string_values(object, "msDS-AllowedToDelegateTo") {
            let target = self.resolve_or_insert_external("service", service, None, None);
            self.add_edge(
                object_id,
                target,
                RelationKind::DelegatesToService,
                None,
                None,
                None,
                None,
            );
        }
    }

    fn add_sid_history_edges(&mut self, object_id: usize, object: &Object) {
        let Some(attribute) = object.get("sIDHistory") else {
            return;
        };
        for value in &attribute.values {
            let Some(bytes) = value.as_octet_bytes() else {
                continue;
            };
            let Ok(sid) = crate::Sid::from_bytes(bytes) else {
                continue;
            };
            let source = self.resolve_or_insert_sid(&sid.to_string());
            self.add_edge(
                source,
                object_id,
                RelationKind::SidHistoryOf,
                None,
                None,
                None,
                None,
            );
        }
    }

    fn add_gpo_edges(&mut self, object_id: usize, object: &Object) {
        for value in string_values(object, "gPLink") {
            for gpo_dn in parse_gplink(value) {
                let gpo = self.resolve_or_insert_dn(&gpo_dn);
                self.add_edge(
                    gpo,
                    object_id,
                    RelationKind::AppliesGpo,
                    None,
                    None,
                    None,
                    None,
                );
            }
        }
    }

    fn resolve_or_insert_dn(&mut self, dn: &str) -> usize {
        let normalized = normalize_dn(dn);
        if let Some(id) = self.dn_index.get(&normalized).copied() {
            return id;
        }
        let name = first_rdn_value(dn).unwrap_or(dn).to_string();
        let id = self.resolve_or_insert_external("unresolved_dn", &name, Some(dn), None);
        self.dn_index.insert(normalized, id);
        id
    }

    fn resolve_or_insert_sid(&mut self, sid: &str) -> usize {
        let normalized = sid.to_ascii_lowercase();
        if let Some(id) = self.sid_index.get(&normalized).copied() {
            return id;
        }
        let id = self.resolve_or_insert_external("unresolved_sid", sid, None, Some(sid));
        self.sid_index.insert(normalized, id);
        id
    }

    fn resolve_or_insert_external(
        &mut self,
        kind: &str,
        name: &str,
        dn: Option<&str>,
        sid: Option<&str>,
    ) -> usize {
        let key = format!("{kind}:{}", name.to_ascii_lowercase());
        if let Some(id) = self.external_index.get(&key).copied() {
            return id;
        }
        let id = self.nodes.len();
        self.nodes.push(GraphNode {
            id,
            name: name.to_string(),
            object_type: kind.to_string(),
            dn: dn.map(str::to_string),
            sid: sid.map(str::to_string),
            attributes: BTreeMap::new(),
            omitted_attribute_count: 0,
            external: true,
        });
        self.outgoing.push(Vec::new());
        self.incoming.push(Vec::new());
        self.external_index.insert(key, id);
        id
    }

    #[allow(clippy::too_many_arguments)]
    fn add_edge(
        &mut self,
        source: usize,
        target: usize,
        relation: RelationKind,
        right: Option<String>,
        inherited: Option<bool>,
        access_mask: Option<String>,
        detail: Option<String>,
    ) {
        let key = format!(
            "{source}|{target}|{}|{}|{}|{}|{}",
            relation.as_str(),
            right.as_deref().unwrap_or(""),
            inherited.map(|value| value.to_string()).unwrap_or_default(),
            access_mask.as_deref().unwrap_or(""),
            detail.as_deref().unwrap_or("")
        );
        if !self.edge_keys.insert(key) {
            return;
        }
        let id = self.edges.len();
        self.edges.push(GraphEdge {
            id,
            source,
            target,
            relation,
            right,
            inherited,
            access_mask,
            detail,
        });
        self.outgoing[source].push(id);
        self.incoming[target].push(id);
    }

    fn is_privileged_group(&self, node_id: usize) -> bool {
        let Some(node) = self.nodes.get(node_id) else {
            return false;
        };
        let name = node.name.to_ascii_lowercase();
        let privileged_name = [
            "domain admins",
            "enterprise admins",
            "schema admins",
            "administrators",
            "account operators",
            "server operators",
            "backup operators",
            "print operators",
            "group policy creator owners",
        ]
        .contains(&name.as_str());
        let privileged_sid = node
            .sid
            .as_deref()
            .map(|sid| {
                [
                    "-512", "-518", "-519", "-520", "-544", "-548", "-549", "-550", "-551",
                ]
                .iter()
                .any(|suffix| sid.ends_with(suffix))
            })
            .unwrap_or(false);
        privileged_name || privileged_sid
    }
}

fn graph_node(id: usize, object: &Object) -> GraphNode {
    let (attributes, omitted_attribute_count) = curated_attributes(object);
    GraphNode {
        id,
        name: object.principal_name(),
        object_type: object.object_type().as_str().to_string(),
        dn: object.dn().map(str::to_string),
        sid: object.object_sid().map(|sid| sid.to_string()),
        attributes,
        omitted_attribute_count,
        external: false,
    }
}

fn curated_attributes(object: &Object) -> (BTreeMap<String, Vec<String>>, usize) {
    let mut attributes = BTreeMap::new();
    let mut omitted = 0usize;
    for (name, attribute) in &object.attributes {
        if !is_ai_visible_attribute(name) {
            omitted += 1;
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if is_relationship_attribute(&lower) {
            continue;
        }
        let values = attribute
            .values
            .iter()
            .take(MAX_ATTRIBUTE_VALUES)
            .map(redacted_value)
            .collect::<Vec<_>>();
        attributes.insert(name.clone(), values);
    }
    (attributes, omitted)
}

fn is_ai_visible_attribute(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "objectclass"
            | "objectcategory"
            | "samaccountname"
            | "userprincipalname"
            | "displayname"
            | "cn"
            | "name"
            | "distinguishedname"
            | "objectsid"
            | "objectguid"
            | "primarygroupid"
            | "useraccountcontrol"
            | "admincount"
            | "iscriticalsystemobject"
            | "pwdlastset"
            | "lastlogon"
            | "lastlogontimestamp"
            | "accountexpires"
            | "whencreated"
            | "whenchanged"
            | "serviceprincipalname"
            | "msds-allowedtodelegateto"
            | "msds-supportedencryptiontypes"
            | "member"
            | "memberof"
            | "manager"
            | "managedby"
            | "gplink"
            | "gpoptions"
            | "ntsecuritydescriptor"
            | "msds-allowedtoactonbehalfofotheridentity"
            | "sidhistory"
    )
}

fn is_relationship_attribute(lower: &str) -> bool {
    matches!(
        lower,
        "member"
            | "memberof"
            | "manager"
            | "managedby"
            | "gplink"
            | "ntsecuritydescriptor"
            | "msds-allowedtoactonbehalfofotheridentity"
            | "msds-allowedtodelegateto"
            | "sidhistory"
    )
}

fn redacted_value(value: &AttributeValue) -> String {
    match value {
        AttributeValue::String(value) => truncate_chars(value, MAX_ATTRIBUTE_VALUE_CHARS),
        AttributeValue::Integer(value) => value.to_string(),
        AttributeValue::LargeInteger(value) => value.to_string(),
        AttributeValue::Boolean(value) => value.to_string(),
        AttributeValue::UtcTime(value) => value.to_string(),
        AttributeValue::OctetString(value) => format!("<binary:{} bytes>", value.len()),
        AttributeValue::NtSecurityDescriptor(value) => {
            format!("<security-descriptor:{} bytes>", value.len())
        }
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    truncated.push_str("…<truncated>");
    truncated
}

fn string_values<'a>(object: &'a Object, name: &str) -> impl Iterator<Item = &'a str> {
    object
        .get(name)
        .into_iter()
        .flat_map(|attribute| attribute.values.iter())
        .filter_map(AttributeValue::as_str)
}

fn first_u32(object: &Object, name: &str) -> Option<u32> {
    match object.get_first(name)? {
        AttributeValue::Integer(value) => Some(*value),
        AttributeValue::LargeInteger(value) => u32::try_from(*value).ok(),
        AttributeValue::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn normalize_dn(dn: &str) -> String {
    dn.trim().to_ascii_lowercase()
}

fn parent_dn(dn: &str) -> Option<String> {
    let mut escaped = false;
    for (index, character) in dn.char_indices() {
        match character {
            '\\' if !escaped => escaped = true,
            ',' if !escaped => return Some(dn[index + 1..].trim().to_string()),
            _ => escaped = false,
        }
    }
    None
}

fn first_rdn_value(dn: &str) -> Option<&str> {
    let first = dn.split(',').next()?;
    first.split_once('=').map(|(_, value)| value.trim())
}

fn parse_gplink(value: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.to_ascii_lowercase().find("ldap://") {
        let after = &rest[start + "ldap://".len()..];
        let end = after
            .find(';')
            .or_else(|| after.find(']'))
            .unwrap_or(after.len());
        let dn = after[..end].trim();
        if !dn.is_empty() {
            links.push(dn.to_string());
        }
        rest = &after[end..];
        if rest.is_empty() {
            break;
        }
        rest = &rest[1..];
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> LdapGraph {
        let snapshot = Snapshot::from_ldif_str(
            "dn: DC=corp,DC=local\nobjectClass: domain\nname: corp\n\n\
             dn: CN=Admins,DC=corp,DC=local\nobjectClass: group\nname: Domain Admins\nmember: CN=alice,DC=corp,DC=local\n\n\
             dn: CN=alice,DC=corp,DC=local\nobjectClass: user\nsAMAccountName: alice\nmemberOf: CN=Admins,DC=corp,DC=local\nunicodePwd: should-never-leave\n",
        )
        .unwrap();
        LdapGraph::from_snapshot(&snapshot)
    }

    #[test]
    fn builds_containment_and_deduplicated_membership() {
        let graph = sample_graph();
        let alice = graph.search_nodes("alice", None, 10)[0].id;
        let admins = graph.search_nodes("Domain Admins", None, 10)[0].id;
        let memberships = graph
            .neighbors(alice, "outgoing", Some(RelationKind::MemberOf), 10)
            .into_iter()
            .filter(|edge| edge.target == admins)
            .count();
        assert_eq!(memberships, 1);
        assert!(graph.summary().relation_types.contains_key("contains"));
    }

    #[test]
    fn omits_non_allowlisted_and_secret_attributes() {
        let graph = sample_graph();
        let alice = graph.search_nodes("alice", None, 10)[0];
        assert!(
            !alice
                .attributes
                .keys()
                .any(|name| name.eq_ignore_ascii_case("unicodePwd"))
        );
        assert!(alice.omitted_attribute_count > 0);
        let json = serde_json::to_string(&graph).unwrap();
        assert!(!json.contains("should-never-leave"));
    }

    #[test]
    fn parses_escaped_parent_dn() {
        assert_eq!(
            parent_dn(r"CN=Doe\, Jane,OU=People,DC=corp,DC=local").as_deref(),
            Some("OU=People,DC=corp,DC=local")
        );
    }
}
