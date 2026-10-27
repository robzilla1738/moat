//! Per-platform snapshot compiler.
//!
//! A rule that needs a capability the platform lacks is rejected (or, for allow rules that opt in, left out
//! and *reported*). Nothing is ever silently compiled into a weaker rule.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability::{Capability, CapabilityAdvertisement, Platform, Support};
use crate::policy::{Action, OnUnsupported, Policy, PolicyError};

pub const SNAPSHOT_SCHEMA: &str = "moat.snapshot.v1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CompileWarning {
    pub rule_id: String,
    pub capability: Capability,
    pub support: Support,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OmittedRule {
    pub rule_id: String,
    pub action: Action,
    pub missing: Vec<Capability>,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct CompileReport {
    pub warnings: Vec<CompileWarning>,
    /// Rules left out of this platform's snapshot, always with a reason. Shown in the Rules preview.
    pub omitted: Vec<OmittedRule>,
    pub expired: Vec<String>,
    pub required_capabilities: BTreeSet<Capability>,
    /// Session profiles that cannot be launched on this platform (the launcher refuses them).
    pub unavailable_session_profiles: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: String,
    /// Monotonic revision. A rollback is a *new* revision whose content is older.
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_of: Option<u64>,
    pub platform: Platform,
    pub adapter: String,
    pub policy_name: String,
    /// sha256 of the canonical JSON of the source policy.
    pub policy_digest: String,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    /// The normalized policy the endpoint evaluates (expired rules dropped, omitted rules removed).
    pub policy: Policy,
    pub report: CompileReport,
}

#[derive(Clone, Debug)]
pub struct CompileOptions {
    pub revision: u64,
    pub rollback_of: Option<u64>,
    pub issued_at: DateTime<Utc>,
    pub not_after: Option<DateTime<Utc>>,
}

pub fn policy_digest(p: &Policy) -> String {
    let bytes = serde_json::to_vec(p).expect("policy serializes");
    hex::encode(Sha256::digest(bytes))
}

pub fn compile(policy: &Policy, adv: &CapabilityAdvertisement, opts: &CompileOptions) -> Result<Snapshot, Vec<PolicyError>> {
    policy.validate()?;
    let mut errors = Vec::new();
    let mut report = CompileReport::default();
    let mut out = policy.clone();
    out.rules.clear();

    let sessions_supported = adv.has(Capability::SessionEnforcement);
    if !sessions_supported {
        let mut profs: BTreeSet<String> = BTreeSet::new();
        for r in &policy.rules {
            if let Some(s) = &r.selector.session {
                profs.extend(s.profiles.iter().cloned());
            }
        }
        report.unavailable_session_profiles = profs.into_iter().collect();
    }

    for (i, r) in policy.rules.iter().enumerate() {
        if r.expires_at.map(|e| e <= opts.issued_at).unwrap_or(false) {
            report.expired.push(r.id.clone());
            continue;
        }
        let caps = policy.implied_capabilities(r);
        // A session-scoped rule on a platform with no session boundary can never match: protected sessions cannot
        // be launched there at all (the launcher refuses). Omitting it changes no other traffic; report it.
        if r.selector.session.is_some() && !sessions_supported {
            report.omitted.push(OmittedRule {
                rule_id: r.id.clone(),
                action: r.action,
                missing: vec![Capability::SessionEnforcement],
                reason: format!("{} has no protected-session boundary; sessions for this profile are refused at launch", adv.adapter),
            });
            continue;
        }
        let mut missing = Vec::new();
        for c in &caps {
            match adv.support(*c) {
                Support::Unsupported => missing.push(*c),
                Support::Partial | Support::Untested => report.warnings.push(CompileWarning {
                    rule_id: r.id.clone(),
                    capability: *c,
                    support: adv.support(*c),
                    note: adv.capabilities.get(c).and_then(|s| s.note.clone()),
                }),
                Support::Supported => {}
            }
        }
        if !missing.is_empty() {
            let names: Vec<&str> = missing.iter().map(|c| c.label()).collect();
            if r.on_unsupported == OnUnsupported::SkipWithReport && r.action == Action::Allow {
                report.omitted.push(OmittedRule {
                    rule_id: r.id.clone(),
                    action: r.action,
                    missing: missing.clone(),
                    reason: format!(
                        "needs {} which {} does not support; omitting this allow makes the platform stricter",
                        names.join(", "),
                        adv.adapter
                    ),
                });
                continue;
            }
            errors.push(PolicyError {
                path: format!("rules[{i}]"),
                message: format!(
                    "rule {} needs {} which {} on {} does not support; refusing to compile a weaker rule",
                    r.id,
                    names.join(", "),
                    adv.adapter,
                    adv.platform.label()
                ),
            });
            continue;
        }
        report.required_capabilities.extend(caps);
        out.rules.push(r.clone());
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Snapshot {
        schema: SNAPSHOT_SCHEMA.into(),
        revision: opts.revision,
        rollback_of: opts.rollback_of,
        platform: adv.platform,
        adapter: adv.adapter.clone(),
        policy_name: policy.name.clone(),
        policy_digest: policy_digest(policy),
        issued_at: opts.issued_at,
        not_after: opts.not_after,
        policy: out,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> CompileOptions {
        CompileOptions { revision: 7, rollback_of: None, issued_at: "2026-10-26T12:00:00Z".parse().unwrap(), not_after: None }
    }

    fn home() -> Policy {
        Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap()
    }

    #[test]
    fn macos_omits_session_rules_with_report() {
        let s = compile(&home(), &CapabilityAdvertisement::macos_network_extension(), &opts()).unwrap();
        assert!(s.policy.rules.iter().all(|r| r.selector.session.is_none()));
        assert!(s.report.unavailable_session_profiles.contains(&"coding-session".to_string()));
        assert!(!s.report.omitted.is_empty());
    }

    #[test]
    fn linux_rejects_hostname_rules_unless_skippable() {
        let mut p = home();
        for r in &mut p.rules {
            r.on_unsupported = OnUnsupported::Reject;
        }
        let errs = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("hostname enforcement")));
        // With the shipped policy the hostname allows opt into skip_with_report: stricter, and reported.
        let s = compile(&home(), &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap();
        assert!(s.report.omitted.iter().any(|o| o.rule_id == "coding-allow-github"));
        assert!(s.policy.rules.iter().any(|r| r.id == "safety-workloads-never-reach-controller"));
    }

    #[test]
    fn expired_rules_are_dropped_and_reported() {
        let mut p = home();
        p.rules[1].expires_at = Some("2026-01-01T00:00:00Z".parse().unwrap());
        let s = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap();
        assert_eq!(s.report.expired, vec![p.rules[1].id.clone()]);
    }

    #[test]
    fn invalid_policy_is_rejected() {
        let mut p = home();
        p.fallback_profile = "nope".into();
        assert!(compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).is_err());
    }
}
