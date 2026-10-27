//! Policy evaluation with an explanation of the winning rule and every rule it overrode.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::enrichment::{match_endpoint, Enricher};
use crate::identity::{AppIdentity, ProcessInstanceId, SessionRef};
use crate::net::{classify, host_matches, HostnameEvidence, NetScope, Transport};
use crate::policy::{Action, AppMatcher, DefaultAction, Destinations, Layer, Policy, ProviderMode, Rule, Selector};

/// One observed connection attempt (an outbound flow before or at the decision point).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FlowAttempt {
    pub id: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInstanceId>,
    pub app: AppIdentity,
    /// Ancestors, nearest first. Only meaningful when `ancestry_complete` says so.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<AppIdentity>,
    #[serde(default)]
    pub ancestry_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionRef>,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<HostnameEvidence>,
    pub at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Winner {
    Rule { id: String, layer: Layer, action: Action, provenance: String },
    ProfileDefault { profile: String, default: DefaultAction },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Overridden {
    pub id: String,
    pub layer: Layer,
    pub action: Action,
    pub why: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// True when the flow was permitted only because the profile is observing. The UI must say so.
    pub permitted_by_observation: bool,
    pub profile: String,
    pub winner: Winner,
    pub overridden: Vec<Overridden>,
    /// Uncertainty and evaluation notes, in plain language.
    pub notes: Vec<String>,
}

impl Decision {
    pub fn summary(&self) -> String {
        let v = match (self.verdict, self.permitted_by_observation) {
            (Verdict::Allow, true) => "permitted (observation, not enforced)",
            (Verdict::Allow, false) => "allowed",
            (Verdict::Deny, _) => "blocked",
        };
        match &self.winner {
            Winner::Rule { id, layer, .. } => format!("{v} by {} rule {id}", layer.label()),
            Winner::ProfileDefault { profile, .. } => format!("{v} by the {profile} profile default"),
        }
    }
}

pub struct EvalContext<'a> {
    pub policy: &'a Policy,
    pub enricher: &'a Enricher,
    /// Device groups the evaluating device belongs to.
    pub device_groups: Vec<String>,
    /// The evaluating device.
    pub device_id: String,
}

impl<'a> EvalContext<'a> {
    pub fn new(policy: &'a Policy, enricher: &'a Enricher, device_id: &str) -> Self {
        let device_groups =
            policy.device_groups.iter().filter(|(_, members)| members.iter().any(|m| m == device_id)).map(|(g, _)| g.clone()).collect();
        EvalContext { policy, enricher, device_groups, device_id: device_id.to_string() }
    }
}

fn app_matches(m: &AppMatcher, a: &AppIdentity) -> bool {
    let eq = |want: &Option<String>, have: &Option<String>| match want {
        None => true,
        Some(w) => have.as_deref() == Some(w.as_str()),
    };
    if !eq(&m.family, &a.family) || !eq(&m.bundle_id, &a.bundle_id) || !eq(&m.team_id, &a.team_id) || !eq(&m.signing_id, &a.signing_id) {
        return false;
    }
    if let Some(e) = &m.executable {
        match (&a.executable, e.strip_prefix("*/")) {
            (None, _) => return false,
            (Some(have), Some(base)) => {
                if have.rsplit('/').next() != Some(base) {
                    return false;
                }
            }
            (Some(have), None) => {
                if have != e {
                    return false;
                }
            }
        }
    }
    true
}

/// Does the selector match this flow? Returns (matched, notes).
fn selector_matches(ctx: &EvalContext, s: &Selector, f: &FlowAttempt, notes: &mut Vec<String>) -> bool {
    if !s.devices.is_empty() && !s.devices.contains(&ctx.device_id) {
        return false;
    }
    if !s.processes.is_empty() {
        // The flow's process instance must be attributed on this device, in the named boot, with the same start
        // generation. Missing attribution never matches.
        let hit = f.process.as_ref().is_some_and(|p| {
            p.device_id == ctx.device_id
                && s.processes.iter().any(|m| m.boot_id == p.boot_id && m.pid == p.pid && m.start_generation == p.start_generation)
        });
        if !hit {
            return false;
        }
    }
    if !s.device_groups.is_empty() && !s.device_groups.iter().any(|g| ctx.device_groups.contains(g)) {
        return false;
    }
    if !s.users.is_empty() && !f.user.as_ref().map(|u| s.users.contains(u)).unwrap_or(false) {
        return false;
    }
    if !s.apps.is_empty() && !s.apps.iter().any(|m| app_matches(m, &f.app)) {
        return false;
    }
    if !s.ancestors.is_empty() {
        let hit = f.ancestors.iter().any(|a| s.ancestors.iter().any(|m| app_matches(m, a)));
        if !hit {
            return false;
        }
        if !f.ancestry_complete {
            notes.push("ancestor match relies on incomplete ancestry".into());
        }
    }
    if let Some(sm) = &s.session {
        match &f.session {
            Some(sess) if sess.verified && sess.boundary.is_containment() => {
                let by_profile =
                    sm.any_protected || sm.profiles.contains(&sess.profile) || (sm.profiles.is_empty() && !sm.session_ids.is_empty());
                let by_instance = sm.session_ids.is_empty() || sm.session_ids.contains(&sess.id);
                if !(by_profile && by_instance) {
                    return false;
                }
            }
            Some(sess) => {
                notes.push(format!(
                    "session {} is not a verified protected session ({}); session rules do not apply",
                    sess.id,
                    sess.boundary.label()
                ));
                return false;
            }
            None => return false,
        }
    }
    true
}

/// Does a destination description match? Returns Some(reason) on match.
fn destinations_match(ctx: &EvalContext, d: &Destinations, f: &FlowAttempt, notes: &mut Vec<String>, depth: u8) -> Option<String> {
    if d.any {
        return Some("any destination".into());
    }
    for c in &d.cidrs {
        if c.contains(&f.remote_ip) {
            return Some(format!("address in {c}"));
        }
    }
    let scope = classify(f.remote_ip);
    if d.scopes.contains(&scope) {
        return Some(format!("{} address", scope.label()));
    }
    if !d.hosts.is_empty() {
        match &f.hostname {
            Some(h) => {
                if let Some(p) = d.hosts.iter().find(|p| host_matches(p, &h.name)) {
                    return Some(format!("hostname {} matches {p} (evidence: {:?}, {:?} confidence)", h.name, h.source, h.confidence));
                }
            }
            None => notes.push("a hostname rule could not be evaluated: no hostname evidence for this flow".into()),
        }
    }
    for pm in &d.providers {
        let by_ip = || {
            ctx.enricher
                .provider_of_ip(f.remote_ip)
                .filter(|(p, r)| {
                    p == &pm.provider && (pm.regions.is_empty() || r.as_ref().map(|r| pm.regions.contains(r)).unwrap_or(false))
                })
                .map(|(p, r)| format!("address in {p} published ranges{}", r.map(|r| format!(" ({r})")).unwrap_or_default()))
        };
        let by_host = || {
            f.hostname
                .as_ref()
                .and_then(|h| match_endpoint(ctx.enricher.patterns(), &h.name))
                .filter(|m| m.provider == pm.provider && (pm.regions.is_empty() || pm.regions.contains(&m.region)))
                .map(|m| format!("hostname matches documented {} {} endpoint for {}", m.provider, m.service, m.region))
        };
        let hit = match pm.mode {
            ProviderMode::KnownIps => by_ip(),
            ProviderMode::RegionEndpoints => by_host(),
            ProviderMode::Both => by_ip().or_else(by_host),
        };
        if let Some(h) = hit {
            return Some(h);
        }
    }
    if depth == 0 {
        for s in &d.sets {
            if let Some(set) = ctx.policy.destination_sets.get(s) {
                if let Some(r) = destinations_match(ctx, &set.destinations, f, notes, depth + 1) {
                    return Some(format!("set {s}: {r}"));
                }
            }
        }
    }
    None
}

fn rule_matches(ctx: &EvalContext, r: &Rule, f: &FlowAttempt, notes: &mut Vec<String>) -> Option<String> {
    if let Some(exp) = r.expires_at {
        if exp <= f.at {
            return None;
        }
    }
    if !r.transport.matches(f.transport) {
        return None;
    }
    if !r.ports.is_empty() && !r.ports.iter().any(|p| p.contains(f.remote_port)) {
        return None;
    }
    if !selector_matches(ctx, &r.selector, f, notes) {
        return None;
    }
    destinations_match(ctx, &r.destinations, f, notes, 0)
}

/// Choose the profile for a flow: a verified protected session's profile; otherwise the first profile whose
/// `applies_to` selects the app; otherwise the fallback.
pub fn profile_for<'p>(ctx: &EvalContext<'p>, f: &FlowAttempt, notes: &mut Vec<String>) -> &'p str {
    if let Some(s) = &f.session {
        if s.verified && s.boundary.is_containment() {
            if let Some(p) = ctx.policy.profile(&s.profile) {
                return &p.id;
            }
            notes.push(format!("session profile {} is not in this policy; using the most restrictive default", s.profile));
            if let Some(p) = ctx.policy.profiles.iter().find(|p| p.default == DefaultAction::Deny) {
                return &p.id;
            }
        }
    }
    for p in &ctx.policy.profiles {
        if p.applies_to.is_everything() || p.applies_to.session.is_some() {
            continue;
        }
        let mut scratch = Vec::new();
        if selector_matches(ctx, &p.applies_to, f, &mut scratch) {
            return &p.id;
        }
    }
    &ctx.policy.fallback_profile
}

/// Evaluate a flow. Precedence: safety > emergency > override > explicit; within a layer deny beats allow;
/// with no matching rule, the profile default applies.
pub fn evaluate(ctx: &EvalContext, f: &FlowAttempt) -> Decision {
    let mut notes = Vec::new();
    let mut matched: Vec<(&Rule, String)> = Vec::new();
    for r in &ctx.policy.rules {
        if let Some(why) = rule_matches(ctx, r, f, &mut notes) {
            matched.push((r, why));
        }
    }
    let profile_id = profile_for(ctx, f, &mut notes).to_string();
    let profile = ctx.policy.profile(&profile_id);
    if let Some(s) = &f.session {
        if !s.verified {
            notes.push(format!("session label {} is unverified and treated as a hint", s.id));
        }
    }
    if f.session.is_none() && !f.ancestry_complete && !f.ancestors.is_empty() {
        notes.push("process ancestry is incomplete".into());
    }

    // Sort by (layer rank, deny first), stable in policy order.
    matched.sort_by_key(|(r, _)| (r.layer.rank(), if r.action == Action::Deny { 0 } else { 1 }));

    if let Some((win, _)) = matched.first() {
        let win_layer = win.layer;
        let win_id = win.id.clone();
        let overridden = matched
            .iter()
            .skip(1)
            .map(|(r, _)| Overridden {
                id: r.id.clone(),
                layer: r.layer,
                action: r.action,
                why: if r.layer != win_layer {
                    format!("{} layer outranks {} layer", win_layer.label(), r.layer.label())
                } else if r.action != win.action {
                    "deny beats allow within the same layer".into()
                } else {
                    format!("{win_id} appears first")
                },
            })
            .collect();
        notes.dedup();
        return Decision {
            verdict: if win.action == Action::Allow { Verdict::Allow } else { Verdict::Deny },
            permitted_by_observation: false,
            profile: profile_id,
            winner: Winner::Rule {
                id: win.id.clone(),
                layer: win.layer,
                action: win.action,
                provenance: format!(
                    "{:?}{}",
                    win.provenance.kind,
                    win.provenance.reference.as_ref().map(|r| format!(" {r}")).unwrap_or_default()
                )
                .to_lowercase(),
            },
            overridden,
            notes,
        };
    }

    let default = profile.map(|p| p.default).unwrap_or(DefaultAction::Deny);
    if profile.is_none() {
        notes.push(format!("profile {profile_id} missing; denying"));
    }
    notes.dedup();
    Decision {
        verdict: if default == DefaultAction::Deny { Verdict::Deny } else { Verdict::Allow },
        permitted_by_observation: default == DefaultAction::Observe,
        profile: profile_id.clone(),
        winner: Winner::ProfileDefault { profile: profile_id, default },
        overridden: Vec::new(),
        notes,
    }
}

/// What the policy can decide about a hostname **before** any DNS lookup (W05).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostnameAdmission {
    /// Denied whatever the name resolves to: no lookup may be made.
    DenyWithoutLookup { reason: String },
    /// A rule allows the name by name; resolve it, then re-check every resolved address.
    ResolveAllowedName,
    /// Only address-based rules could allow it, so the name must be resolved to know. This is a DNS exposure the
    /// policy implies (the name is not permitted by name) and is reported as such.
    ResolveForAddressRules,
}

fn dest_matches_name(ctx: &EvalContext, d: &Destinations, host: &str, depth: u8) -> bool {
    if d.hosts.iter().any(|p| host_matches(p, host)) {
        return true;
    }
    if d.providers.iter().any(|pm| {
        pm.mode != ProviderMode::KnownIps
            && match_endpoint(ctx.enricher.patterns(), host)
                .is_some_and(|m| m.provider == pm.provider && (pm.regions.is_empty() || pm.regions.contains(&m.region)))
    }) {
        return true;
    }
    depth == 0
        && d.sets.iter().any(|s| ctx.policy.destination_sets.get(s).is_some_and(|set| dest_matches_name(ctx, &set.destinations, host, 1)))
}

/// Could this destination match some address, independent of the name?
fn dest_address_dependent(ctx: &EvalContext, d: &Destinations, depth: u8) -> bool {
    d.any
        || !d.cidrs.is_empty()
        || !d.scopes.is_empty()
        || d.providers.iter().any(|pm| pm.mode != ProviderMode::RegionEndpoints)
        || (depth == 0
            && d.sets
                .iter()
                .any(|s| ctx.policy.destination_sets.get(s).is_some_and(|set| dest_address_dependent(ctx, &set.destinations, 1))))
}

/// Decide what may happen to a hostname before resolving it. `f` carries the hostname evidence, port, transport,
/// session and time; its address is ignored. Exact with respect to [`evaluate`]: `DenyWithoutLookup` is returned
/// only when no resolved address could make any allow win.
pub fn hostname_admission(ctx: &EvalContext, f: &FlowAttempt) -> HostnameAdmission {
    let Some(h) = &f.hostname else { return HostnameAdmission::ResolveForAddressRules };
    let mut notes = Vec::new();
    let mut name_deny: Option<(u8, String)> = None;
    let mut allow_rank: Option<u8> = None;
    let mut name_allow = false;
    for r in &ctx.policy.rules {
        if r.expires_at.is_some_and(|e| e <= f.at) || !r.transport.matches(f.transport) {
            continue;
        }
        if !r.ports.is_empty() && !r.ports.iter().any(|p| p.contains(f.remote_port)) {
            continue;
        }
        if !selector_matches(ctx, &r.selector, f, &mut notes) {
            continue;
        }
        let by_name = dest_matches_name(ctx, &r.destinations, &h.name, 0);
        let by_addr = dest_address_dependent(ctx, &r.destinations, 0);
        match r.action {
            Action::Deny if by_name => {
                if name_deny.as_ref().map_or(true, |(rank, _)| r.layer.rank() < *rank) {
                    name_deny = Some((r.layer.rank(), r.id.clone()));
                }
            }
            Action::Allow if by_name || by_addr => {
                name_allow |= by_name;
                allow_rank = Some(allow_rank.map_or(r.layer.rank(), |a| a.min(r.layer.rank())));
            }
            _ => {}
        }
    }
    let profile_id = profile_for(ctx, f, &mut notes).to_string();
    let default = ctx.policy.profile(&profile_id).map(|p| p.default).unwrap_or(DefaultAction::Deny);
    if let Some((rank, id)) = &name_deny {
        // a deny wins against allows in lower layers and (deny beats allow) in its own layer
        if allow_rank.map_or(true, |a| a >= *rank) {
            return HostnameAdmission::DenyWithoutLookup { reason: format!("{} is denied by rule {id} whatever it resolves to", h.name) };
        }
    }
    if allow_rank.is_none() && default == DefaultAction::Deny {
        return HostnameAdmission::DenyWithoutLookup {
            reason: format!("no rule can allow {} and the {profile_id} profile denies by default", h.name),
        };
    }
    if name_allow {
        HostnameAdmission::ResolveAllowedName
    } else {
        HostnameAdmission::ResolveForAddressRules
    }
}

/// Convenience: a scope check used by UI copy.
pub fn scope_of(f: &FlowAttempt) -> NetScope {
    classify(f.remote_ip)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity::Boundary;
    use crate::net::{Confidence, HostnameSource};

    pub fn policy() -> Policy {
        Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap()
    }

    pub fn flow(app: &str, ip: &str, port: u16, host: Option<&str>, session: Option<&str>) -> FlowAttempt {
        FlowAttempt {
            id: "f1".into(),
            device_id: "mbp-m1".into(),
            user: Some("robert".into()),
            process: None,
            app: AppIdentity { family: Some(app.into()), executable: Some(format!("/usr/bin/{app}")), ..Default::default() },
            ancestors: vec![],
            ancestry_complete: true,
            session: session.map(|p| SessionRef { id: "s1".into(), profile: p.into(), boundary: Boundary::LinuxCgroup, verified: true }),
            remote_ip: ip.parse().unwrap(),
            remote_port: port,
            transport: Transport::Tcp,
            hostname: host.map(|h| HostnameEvidence { name: h.into(), source: HostnameSource::FlowApi, confidence: Confidence::High }),
            at: "2026-10-26T12:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn ordinary_app_is_observed() {
        let p = policy();
        p.validate().unwrap();
        let e = Enricher::new();
        let ctx = EvalContext::new(&p, &e, "mbp-m1");
        let d = evaluate(&ctx, &flow("safari", "198.51.100.10", 443, Some("example.com"), None));
        assert_eq!(d.verdict, Verdict::Allow);
        assert!(d.permitted_by_observation);
    }

    #[test]
    fn coding_session_default_deny_and_github_allowed() {
        let p = policy();
        let e = Enricher::new();
        let ctx = EvalContext::new(&p, &e, "mbp-m1");
        let d = evaluate(&ctx, &flow("curl", "198.51.100.10", 443, Some("oss-cn-beijing.aliyuncs.com"), Some("coding-session")));
        assert_eq!(d.verdict, Verdict::Deny);
        let d = evaluate(&ctx, &flow("git", "198.51.100.11", 443, Some("api.github.com"), Some("coding-session")));
        assert_eq!(d.verdict, Verdict::Allow, "{d:?}");
    }

    #[test]
    fn lan_exception_does_not_defeat_workload_deny() {
        let p = policy();
        let e = Enricher::new();
        let ctx = EvalContext::new(&p, &e, "mbp-m1");
        // controller admin address is denied to workloads by a safety rule even though LAN is allowed for private-services
        let d = evaluate(&ctx, &flow("python3", "192.168.1.2", 8443, None, Some("private-services-only")));
        assert_eq!(d.verdict, Verdict::Deny, "{d:?}");
        assert!(!d.overridden.is_empty());
    }

    #[test]
    fn unverified_session_does_not_get_session_rules() {
        let p = policy();
        let e = Enricher::new();
        let ctx = EvalContext::new(&p, &e, "mbp-m1");
        let mut f = flow("git", "198.51.100.11", 443, Some("api.github.com"), Some("coding-session"));
        f.session.as_mut().unwrap().verified = false;
        let d = evaluate(&ctx, &f);
        assert!(d.notes.iter().any(|n| n.contains("unverified")));
        assert!(d.permitted_by_observation, "falls back to the ordinary profile, labeled as observation");
    }

    #[test]
    fn expired_rule_is_ignored() {
        let mut p = policy();
        let e = Enricher::new();
        for r in &mut p.rules {
            if r.id == "coding-allow-github" {
                r.expires_at = Some("2026-01-01T00:00:00Z".parse().unwrap());
            }
        }
        let ctx = EvalContext::new(&p, &e, "mbp-m1");
        let d = evaluate(&ctx, &flow("git", "198.51.100.11", 443, Some("api.github.com"), Some("coding-session")));
        assert_eq!(d.verdict, Verdict::Deny);
    }

    #[test]
    fn hostname_rule_without_evidence_notes_it() {
        let p = policy();
        let e = Enricher::new();
        let ctx = EvalContext::new(&p, &e, "mbp-m1");
        let d = evaluate(&ctx, &flow("git", "198.51.100.11", 443, None, Some("coding-session")));
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d.notes.iter().any(|n| n.contains("no hostname evidence")));
    }
}
