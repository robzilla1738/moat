//! Strict declarative policy schema (`moat.policy.v1`).
//!
//! Policy is data. There are no scripts, hooks or expressions. Unknown fields are rejected.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::net::{validate_host_pattern, NetScope, PortRange, Transport};

pub const POLICY_SCHEMA: &str = "moat.policy.v1";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

/// Precedence layer. Higher layers always win over lower ones. Within a layer, deny wins over allow.
///
/// 1. `safety`    immutable safety/administration constraints (where configured)
/// 2. `emergency` emergency deny
/// 3. `override`  owner-authorized, scoped, expiring override (audited)
/// 4. `explicit`  explicit deny beats narrow allow
/// 5. profile default
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Safety,
    Emergency,
    Override,
    #[default]
    Explicit,
}

impl Layer {
    /// Lower number = higher precedence.
    pub fn rank(&self) -> u8 {
        match self {
            Layer::Safety => 0,
            Layer::Emergency => 1,
            Layer::Override => 2,
            Layer::Explicit => 3,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Layer::Safety => "immutable safety",
            Layer::Emergency => "emergency",
            Layer::Override => "owner override",
            Layer::Explicit => "explicit",
        }
    }
}

/// Where a rule came from. Provenance is shown in every explanation.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    /// Reviewed change in the Git policy repository.
    Git,
    /// Prepared in the UI and authorized by a trusted local owner action.
    OwnerAction,
    /// Expiring overlay grant (e.g. "Allow once for this session").
    TemporaryGrant,
    /// Expanded from a versioned service pack.
    ServicePack,
    /// Built-in safety constraint.
    BuiltIn,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub kind: ProvenanceKind,
    /// Commit, pack id@version, grant id or owner action id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Audit record id; required for overrides and temporary grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
}

/// How cloud provider matching is meant. "Nothing may reach Alibaba Cloud" must say which.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    /// Addresses in a downloaded provider IP dataset.
    KnownIps,
    /// Hostnames matching documented region endpoint patterns.
    RegionEndpoints,
    #[default]
    Both,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderMatch {
    /// Provider id from the enrichment dataset, e.g. `alibaba-cloud`.
    pub provider: String,
    /// Optional region ids, e.g. `cn-beijing`. Empty = any region.
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub mode: ProviderMode,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Destinations {
    /// Exact hostnames or leading-wildcard patterns. Matched against hostname evidence only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<NetScope>,
    /// Named destination sets defined in the policy (or expanded from service packs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<ProviderMatch>,
    /// Matches every destination. Must be explicit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub any: bool,
}

impl Destinations {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
            && self.cidrs.is_empty()
            && self.scopes.is_empty()
            && self.sets.is_empty()
            && self.providers.is_empty()
            && !self.any
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DestinationSet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(flatten)]
    pub destinations: Destinations,
}

/// Application matcher. All present fields must match.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AppMatcher {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    /// Absolute path, or `*/name` to match a basename anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
}

impl AppMatcher {
    pub fn is_empty(&self) -> bool {
        self.family.is_none()
            && self.bundle_id.is_none()
            && self.team_id.is_none()
            && self.signing_id.is_none()
            && self.executable.is_none()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct SessionMatch {
    /// Session profiles, e.g. `coding-session`. Empty with `any_protected` = every verified protected session.
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub any_protected: bool,
    /// Bind to specific protected-session instances (as issued by the endpoint's launcher). Only for expiring
    /// temporary grants / owner overrides, e.g. "Allow once for this session". Combined with `profiles`, both must
    /// match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_ids: Vec<String>,
}

/// One process instance: boot plus pid plus start generation (never a pid alone).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ProcessMatch {
    pub boot_id: String,
    pub pid: u32,
    pub start_generation: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    /// Exact device ids. A grant for one device names it here, so the same executable elsewhere never matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    /// Any one matcher matching is enough.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<AppMatcher>,
    /// Matches when any process in the (verified) ancestry matches. Requires ancestor attribution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<AppMatcher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionMatch>,
    /// Exact process instances (device given by `devices`). Needs process-instance enforcement; a restarted process
    /// (new start generation) or a new boot never matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<ProcessMatch>,
}

impl Selector {
    pub fn is_everything(&self) -> bool {
        self.devices.is_empty()
            && self.processes.is_empty()
            && self.device_groups.is_empty()
            && self.users.is_empty()
            && self.apps.is_empty()
            && self.ancestors.is_empty()
            && self.session.is_none()
    }
    /// "Narrow" = scoped to an app, a session or a process instance.
    pub fn is_narrow(&self) -> bool {
        !self.apps.is_empty() || self.session.is_some() || !self.processes.is_empty()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnUnsupported {
    /// Reject the whole policy for that platform (default, strict).
    #[default]
    Reject,
    /// Leave the rule out of that platform's snapshot and list it in the compile report. Only allowed for
    /// allow rules (skipping an allow can only make things stricter).
    SkipWithReport,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub action: Action,
    #[serde(default)]
    pub layer: Layer,
    #[serde(default)]
    pub selector: Selector,
    pub destinations: Destinations,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub provenance: Provenance,
    /// Capabilities this rule needs in addition to the ones implied by its selectors and destinations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Capability>,
    #[serde(default)]
    pub on_unsupported: OnUnsupported,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// Permit and record. The UI must say traffic is permitted.
    Observe,
    Allow,
    Deny,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum LearningMode {
    /// Ordinary apps: labeled observation period.
    #[default]
    Observe,
    /// High-risk sessions: start restrictive, learn from blocked attempts and approved packs.
    Restrictive,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub default: DefaultAction,
    #[serde(default)]
    pub learning: LearningMode,
    /// Apps/sessions this profile applies to. A protected session uses the profile named by the session.
    #[serde(default)]
    pub applies_to: Selector,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Group name -> device ids.
    #[serde(default)]
    pub device_groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub destination_sets: BTreeMap<String, DestinationSet>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Profile for ordinary apps no other profile claims.
    pub fallback_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyError {
    /// Path to the offending item, e.g. `rules[3].destinations.hosts[0]`.
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

fn err(path: impl Into<String>, msg: impl Into<String>) -> PolicyError {
    PolicyError { path: path.into(), message: msg.into() }
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':' || c == '@')
}

impl Policy {
    /// Parse from TOML or JSON (detected by first non-space character).
    pub fn parse(text: &str) -> Result<Policy, PolicyError> {
        let trimmed = text.trim_start();
        let p: Policy = if trimmed.starts_with('{') {
            serde_json::from_str(text).map_err(|e| err("$", format!("invalid JSON policy: {e}")))?
        } else {
            toml::from_str(text).map_err(|e| err("$", format!("invalid TOML policy: {e}")))?
        };
        Ok(p)
    }

    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Structural validation independent of any platform.
    pub fn validate(&self) -> Result<(), Vec<PolicyError>> {
        let mut errors = Vec::new();
        if self.schema != POLICY_SCHEMA {
            errors.push(err("schema", format!("expected {POLICY_SCHEMA}, got {:?}", self.schema)));
        }
        if self.name.trim().is_empty() {
            errors.push(err("name", "policy name is required"));
        }
        let mut profile_ids = BTreeSet::new();
        for (i, p) in self.profiles.iter().enumerate() {
            if !valid_id(&p.id) {
                errors.push(err(format!("profiles[{i}].id"), "invalid id"));
            }
            if !profile_ids.insert(p.id.clone()) {
                errors.push(err(format!("profiles[{i}].id"), format!("duplicate profile id {:?}", p.id)));
            }
            self.validate_selector(&p.applies_to, &format!("profiles[{i}].applies_to"), &mut errors);
            if p.learning == LearningMode::Restrictive && p.default != DefaultAction::Deny {
                errors
                    .push(err(format!("profiles[{i}]"), "a restrictive-learning profile must default to deny (time never promotes trust)"));
            }
        }
        if !profile_ids.contains(&self.fallback_profile) {
            errors.push(err("fallback_profile", format!("unknown profile {:?}", self.fallback_profile)));
        }
        for (name, set) in &self.destination_sets {
            if !valid_id(name) {
                errors.push(err(format!("destination_sets.{name}"), "invalid set name"));
            }
            if !set.destinations.sets.is_empty() {
                errors.push(err(format!("destination_sets.{name}.sets"), "destination sets cannot nest"));
            }
            if set.destinations.any {
                errors.push(err(format!("destination_sets.{name}.any"), "a destination set cannot be 'any'"));
            }
            self.validate_destinations(&set.destinations, &format!("destination_sets.{name}"), &mut errors);
        }
        let mut rule_ids = BTreeSet::new();
        for (i, r) in self.rules.iter().enumerate() {
            let path = format!("rules[{i}]");
            if !valid_id(&r.id) {
                errors.push(err(format!("{path}.id"), "invalid id"));
            }
            if !rule_ids.insert(r.id.clone()) {
                errors.push(err(format!("{path}.id"), format!("duplicate rule id {:?}", r.id)));
            }
            if r.destinations.is_empty() {
                errors.push(err(format!("{path}.destinations"), "a rule must name destinations (use any = true explicitly)"));
            }
            self.validate_destinations(&r.destinations, &format!("{path}.destinations"), &mut errors);
            self.validate_selector(&r.selector, &format!("{path}.selector"), &mut errors);
            match r.layer {
                Layer::Emergency if r.action != Action::Deny => {
                    errors.push(err(format!("{path}.layer"), "emergency rules can only deny"));
                }
                Layer::Override => {
                    if r.action != Action::Allow {
                        errors.push(err(format!("{path}.layer"), "override rules can only allow; use explicit or emergency deny"));
                    }
                    if r.expires_at.is_none() {
                        errors.push(err(format!("{path}.expires_at"), "an owner override needs an expiration"));
                    }
                    if !r.selector.is_narrow() {
                        errors.push(err(format!("{path}.selector"), "an owner override must be scoped to an app or session"));
                    }
                    if r.provenance.audit_ref.is_none() || r.provenance.kind != ProvenanceKind::OwnerAction {
                        errors.push(err(format!("{path}.provenance"), "an owner override needs owner_action provenance with an audit_ref"));
                    }
                }
                Layer::Safety => {
                    if matches!(r.provenance.kind, ProvenanceKind::TemporaryGrant | ProvenanceKind::ServicePack) {
                        errors.push(err(format!("{path}.provenance"), "safety constraints cannot come from a grant or pack"));
                    }
                    if r.expires_at.is_some() {
                        errors.push(err(format!("{path}.expires_at"), "immutable safety constraints do not expire"));
                    }
                }
                _ => {}
            }
            if r.provenance.kind == ProvenanceKind::TemporaryGrant {
                if r.expires_at.is_none() {
                    errors.push(err(format!("{path}.expires_at"), "temporary grants must expire"));
                }
                if r.provenance.audit_ref.is_none() {
                    errors.push(err(format!("{path}.provenance.audit_ref"), "temporary grants need an audit record"));
                }
                if r.action != Action::Allow {
                    errors.push(err(format!("{path}.action"), "temporary grants only allow"));
                }
                if !r.selector.is_narrow() {
                    errors.push(err(format!("{path}.selector"), "temporary grants must be scoped to an app or session"));
                }
            }
            if r.selector.session.as_ref().is_some_and(|sm| !sm.session_ids.is_empty())
                && (r.action != Action::Allow || r.expires_at.is_none())
            {
                errors.push(err(
                    format!("{path}.selector.session.session_ids"),
                    "rules bound to session instances must be expiring allows (temporary grants)",
                ));
            }
            if r.on_unsupported == OnUnsupported::SkipWithReport && r.action == Action::Deny {
                errors.push(err(
                    format!("{path}.on_unsupported"),
                    "a deny rule cannot be skipped on unsupported platforms (that would silently weaken policy)",
                ));
            }
            if r.ports.len() > 64 {
                errors.push(err(format!("{path}.ports"), "too many port ranges"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_selector(&self, s: &Selector, path: &str, errors: &mut Vec<PolicyError>) {
        for d in &s.devices {
            if !valid_id(d) {
                errors.push(err(format!("{path}.devices"), format!("invalid device id {d:?}")));
            }
        }
        if !s.processes.is_empty() && s.devices.len() != 1 {
            errors.push(err(format!("{path}.processes"), "process instances belong to exactly one device; name it in devices"));
        }
        for p in &s.processes {
            if !valid_id(&p.boot_id) {
                errors.push(err(format!("{path}.processes"), "invalid boot id"));
            }
        }
        for g in &s.device_groups {
            if !self.device_groups.contains_key(g) {
                errors.push(err(format!("{path}.device_groups"), format!("unknown device group {g:?}")));
            }
        }
        for (i, a) in s.apps.iter().chain(s.ancestors.iter()).enumerate() {
            if a.is_empty() {
                errors.push(err(format!("{path}.apps[{i}]"), "empty app matcher matches nothing useful"));
            }
            if let Some(e) = &a.executable {
                if !(e.starts_with('/') || e.starts_with("*/")) {
                    errors.push(err(format!("{path}.apps[{i}].executable"), "use an absolute path or */basename"));
                }
            }
        }
        if let Some(sm) = &s.session {
            if sm.profiles.is_empty() && !sm.any_protected && sm.session_ids.is_empty() {
                errors.push(err(format!("{path}.session"), "name session profiles, session ids, or set any_protected"));
            }
            for id in &sm.session_ids {
                if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                    errors.push(err(format!("{path}.session.session_ids"), format!("invalid session id {id:?}")));
                }
            }
            for p in &sm.profiles {
                if self.profile(p).is_none() {
                    errors.push(err(format!("{path}.session.profiles"), format!("unknown profile {p:?}")));
                }
            }
        }
    }

    fn validate_destinations(&self, d: &Destinations, path: &str, errors: &mut Vec<PolicyError>) {
        for (i, h) in d.hosts.iter().enumerate() {
            if let Err(e) = validate_host_pattern(h) {
                errors.push(err(format!("{path}.hosts[{i}]"), e));
            }
        }
        for s in &d.sets {
            if !self.destination_sets.contains_key(s) {
                errors.push(err(format!("{path}.sets"), format!("unknown destination set {s:?}")));
            }
        }
        for (i, p) in d.providers.iter().enumerate() {
            if !valid_id(&p.provider) {
                errors.push(err(format!("{path}.providers[{i}]"), "invalid provider id"));
            }
        }
        if d.any && (!d.hosts.is_empty() || !d.cidrs.is_empty() || !d.scopes.is_empty() || !d.sets.is_empty() || !d.providers.is_empty()) {
            errors.push(err(format!("{path}.any"), "'any' cannot be combined with other destinations"));
        }
    }

    /// Capabilities a rule implicitly needs, from what it references.
    pub fn implied_capabilities(&self, r: &Rule) -> BTreeSet<Capability> {
        let mut caps: BTreeSet<Capability> = r.requires.iter().copied().collect();
        if !r.selector.apps.is_empty() {
            caps.insert(Capability::AppEnforcement);
        }
        if !r.selector.ancestors.is_empty() {
            caps.insert(Capability::AncestorAttribution);
        }
        if r.selector.session.is_some() {
            caps.insert(Capability::SessionEnforcement);
        }
        if !r.selector.users.is_empty() {
            caps.insert(Capability::UserEnforcement);
        }
        if !r.selector.processes.is_empty() {
            caps.insert(Capability::ProcessEnforcement);
        }
        let mut uses_hosts = !r.destinations.hosts.is_empty();
        let mut v6 = r.destinations.cidrs.iter().any(|c| matches!(c, IpNet::V6(_)));
        for s in &r.destinations.sets {
            if let Some(set) = self.destination_sets.get(s) {
                uses_hosts |= !set.destinations.hosts.is_empty();
                v6 |= set.destinations.cidrs.iter().any(|c| matches!(c, IpNet::V6(_)));
            }
        }
        if r.destinations.providers.iter().any(|p| p.mode != ProviderMode::KnownIps) {
            uses_hosts = true;
        }
        if uses_hosts {
            caps.insert(Capability::HostnameEnforcement);
        }
        if v6 {
            caps.insert(Capability::Ipv6Enforcement);
        }
        if r.transport == Transport::Udp {
            caps.insert(Capability::UdpEnforcement);
        }
        caps
    }

    /// Drop rules that expired before `now`.
    pub fn without_expired(&self, now: DateTime<Utc>) -> Policy {
        let mut p = self.clone();
        p.rules.retain(|r| r.expires_at.map(|e| e > now).unwrap_or(true));
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> &'static str {
        r#"
schema = "moat.policy.v1"
name = "home"
fallback_profile = "ordinary-desktop-learning"

[device_groups]
laptops = ["mbp-m1", "mbp-2"]

[destination_sets.github]
description = "GitHub fetch/push"
hosts = ["github.com", "api.github.com", "*.githubusercontent.com"]

[[profiles]]
id = "ordinary-desktop-learning"
default = "observe"

[[profiles]]
id = "coding-session"
default = "deny"
learning = "restrictive"

[[rules]]
id = "coding-allow-github"
action = "allow"
selector = { session = { profiles = ["coding-session"] } }
destinations = { sets = ["github"] }
transport = "tcp"
ports = [443]
provenance = { kind = "git", reference = "abc123" }
"#
    }

    #[test]
    fn parses_and_validates_toml() {
        let p = Policy::parse(sample()).unwrap();
        p.validate().unwrap();
        assert_eq!(p.rules.len(), 1);
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = sample().replace("transport = \"tcp\"", "transport = \"tcp\"\nscript = \"rm -rf /\"");
        assert!(Policy::parse(&bad).is_err());
    }

    #[test]
    fn rejects_override_without_expiry() {
        let mut p = Policy::parse(sample()).unwrap();
        let mut r = p.rules[0].clone();
        r.id = "ov".into();
        r.layer = Layer::Override;
        p.rules.push(r);
        let errs = p.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("expiration")));
        assert!(errs.iter().any(|e| e.message.contains("audit_ref")));
    }

    #[test]
    fn rejects_skipping_denies() {
        let mut p = Policy::parse(sample()).unwrap();
        p.rules[0].action = Action::Deny;
        p.rules[0].on_unsupported = OnUnsupported::SkipWithReport;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_restrictive_profile_that_allows() {
        let mut p = Policy::parse(sample()).unwrap();
        p.profiles[1].default = DefaultAction::Observe;
        assert!(p.validate().is_err());
    }

    #[test]
    fn implied_caps() {
        let p = Policy::parse(sample()).unwrap();
        let caps = p.implied_capabilities(&p.rules[0]);
        assert!(caps.contains(&Capability::SessionEnforcement));
        assert!(caps.contains(&Capability::HostnameEnforcement));
        assert!(!caps.contains(&Capability::UdpEnforcement));
    }
}
