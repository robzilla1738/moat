//! Per-platform snapshot compiler.
//!
//! A rule that needs a capability the platform lacks is rejected (or, for allow rules that opt in, left out
//! and *reported*). Nothing is ever silently compiled into a weaker rule.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability::{Capability, CapabilityAdvertisement, Platform, Support};
use crate::contracts::{Disposition, ItemDisposition, Omission};
use crate::net::Transport;
use crate::policy::{Action, DefaultAction, OnUnsupported, Policy, PolicyError, Profile};

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
    /// Per-profile and per-rule dispositions (contracts `moat.capability_dispositions.v1` items). Compiled items are
    /// `implemented_unproven`: compilation alone never proves an installed capability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ItemDisposition>,
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

fn capability_name(c: Capability) -> String {
    serde_json::to_value(c).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn restrictiveness(d: DefaultAction) -> u8 {
    match d {
        DefaultAction::Deny => 2,
        DefaultAction::Observe => 1,
        DefaultAction::Allow => 0,
    }
}

/// Capabilities a profile's `applies_to` needs to select its flows.
pub fn profile_capabilities(p: &Profile) -> BTreeSet<Capability> {
    let mut caps = BTreeSet::new();
    if !p.applies_to.apps.is_empty() {
        caps.insert(Capability::AppEnforcement);
    }
    if !p.applies_to.ancestors.is_empty() {
        caps.insert(Capability::AncestorAttribution);
    }
    if !p.applies_to.users.is_empty() {
        caps.insert(Capability::UserEnforcement);
    }
    caps
}

/// Profiles are capability-checked like rules (W02, D-PROFILE-CAPABILITY). A profile whose selector the backend
/// cannot evaluate would silently hand its flows to the fallback profile. That is accepted (and reported) only when
/// the fallback is at least as restrictive; otherwise the policy is rejected for this platform.
fn check_profiles(
    policy: &Policy,
    adv: &CapabilityAdvertisement,
    sessions_supported: bool,
    report: &mut CompileReport,
    errors: &mut Vec<PolicyError>,
) {
    let fallback = policy.profile(&policy.fallback_profile).map(|p| p.default).unwrap_or(DefaultAction::Deny);
    for (i, p) in policy.profiles.iter().enumerate() {
        let session_only = p.applies_to.session.is_some();
        let mut missing: Vec<Capability> =
            profile_capabilities(p).into_iter().filter(|c| adv.support(*c) == Support::Unsupported).collect();
        if session_only && !sessions_supported {
            missing.push(Capability::SessionEnforcement);
        }
        let restrictive = p.default == DefaultAction::Deny;
        if missing.is_empty() {
            let unavailable = !sessions_supported && report.unavailable_session_profiles.contains(&p.id);
            report.items.push(ItemDisposition {
                item: format!("profile:{}", p.id),
                restrictive,
                disposition: if unavailable { Disposition::OmittedAccepted } else { Disposition::ImplementedUnproven },
                omission: unavailable.then_some(Omission::SubjectUnavailable),
                missing: vec![],
                note: (!sessions_supported && report.unavailable_session_profiles.contains(&p.id))
                    .then(|| "protected sessions are refused at launch on this platform".to_string()),
            });
            continue;
        }
        let mut names: Vec<String> = missing.iter().map(|c| capability_name(*c)).collect();
        names.sort();
        names.dedup();
        if session_only || (!restrictive && restrictiveness(fallback) >= restrictiveness(p.default)) {
            report.items.push(ItemDisposition {
                item: format!("profile:{}", p.id),
                restrictive,
                disposition: Disposition::OmittedAccepted,
                omission: Some(if session_only { Omission::SubjectUnavailable } else { Omission::Stricter }),
                missing: names.clone(),
                note: Some(format!(
                    "{} cannot select this profile's flows; they fall to the fallback profile {}, which is at least as strict",
                    adv.adapter, policy.fallback_profile
                )),
            });
        } else {
            let labels: Vec<&str> = missing.iter().map(|c| c.label()).collect();
            errors.push(PolicyError {
                path: format!("profiles[{i}]"),
                message: format!(
                    "profile {} needs {} which {} on {} does not support; its flows would silently fall back to the less \
                     restrictive profile {} (refusing to compile)",
                    p.id,
                    labels.join(", "),
                    adv.adapter,
                    adv.platform.label(),
                    policy.fallback_profile
                ),
            });
        }
    }
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
        // Hostname rules scoped to protected sessions can be enforced for TCP by a session egress proxy that reads
        // the TLS SNI / HTTP CONNECT target (no TLS interception). UDP has no hostname evidence there, so a hostname
        // deny must be TCP-only (otherwise it would silently not cover UDP); a hostname allow on any transport is
        // enforced for TCP only, which is stricter, and is reported as a warning.
        if missing.contains(&Capability::HostnameEnforcement)
            && r.selector.session.is_some()
            && adv.has(Capability::SessionHostnameProxy)
            && missing.iter().all(|c| *c == Capability::HostnameEnforcement)
        {
            if r.action == Action::Deny && r.transport != Transport::Tcp {
                errors.push(PolicyError {
                    path: format!("rules[{i}]"),
                    message: format!(
                        "rule {} denies hostnames on transport {:?}; the {} session proxy sees hostnames for TCP only, \
                         so set transport = \"tcp\" (refusing to compile a deny that would not cover UDP)",
                        r.id, r.transport, adv.adapter
                    ),
                });
                continue;
            }
            missing.clear();
            let note = adv.capabilities.get(&Capability::SessionHostnameProxy).and_then(|s| s.note.clone());
            report.warnings.push(CompileWarning {
                rule_id: r.id.clone(),
                capability: Capability::SessionHostnameProxy,
                support: adv.support(Capability::SessionHostnameProxy),
                note: Some(match (r.action, r.transport) {
                    (Action::Allow, t) if t != Transport::Tcp => {
                        format!("enforced for TCP only (UDP to these hosts stays denied); {}", note.unwrap_or_default())
                    }
                    _ => note.unwrap_or_default(),
                }),
            });
            report.required_capabilities.insert(Capability::SessionHostnameProxy);
            report.required_capabilities.extend(caps.iter().copied().filter(|c| *c != Capability::HostnameEnforcement));
            out.rules.push(r.clone());
            continue;
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
    check_profiles(policy, adv, sessions_supported, &mut report, &mut errors);
    if adv.platform == Platform::Linux {
        errors.extend(crate::backend_ids::linux_collisions(policy));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    for r in &out.rules {
        report.items.push(ItemDisposition {
            item: format!("rule:{}", r.id),
            restrictive: r.action == Action::Deny,
            disposition: Disposition::ImplementedUnproven,
            omission: None,
            missing: vec![],
            note: None,
        });
    }
    for o in &report.omitted {
        let mut missing: Vec<String> = o.missing.iter().map(|c| capability_name(*c)).collect();
        missing.sort();
        missing.dedup();
        report.items.push(ItemDisposition {
            item: format!("rule:{}", o.rule_id),
            restrictive: o.action == Action::Deny,
            disposition: Disposition::OmittedAccepted,
            // Session rules on a platform without sessions can never match; any other omission is an allow.
            omission: Some(if o.missing.contains(&Capability::SessionEnforcement) {
                Omission::SubjectUnavailable
            } else {
                Omission::Stricter
            }),
            missing,
            note: Some(o.reason.clone()),
        });
    }
    report.items.sort_by(|a, b| a.item.cmp(&b.item));
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
        let errs = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup_ip_only(), &opts()).unwrap_err();
        assert!(errs.iter().any(|e| e.message.contains("hostname enforcement")));
        // With the shipped policy the hostname allows opt into skip_with_report: stricter, and reported.
        let s = compile(&home(), &CapabilityAdvertisement::linux_nftables_cgroup_ip_only(), &opts()).unwrap();
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

    #[test]
    fn session_hostname_rules_use_the_proxy_capability() {
        let mut p = home();
        for r in &mut p.rules {
            r.on_unsupported = OnUnsupported::Reject;
        }
        let s = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap();
        assert!(s.report.omitted.is_empty(), "{:?}", s.report.omitted);
        assert!(s.policy.rules.iter().any(|r| r.id == "coding-allow-github"));
        assert!(s.report.required_capabilities.contains(&Capability::SessionHostnameProxy));
        assert!(!s.report.required_capabilities.contains(&Capability::HostnameEnforcement));
        let w = s.report.warnings.iter().find(|w| w.rule_id == "coding-allow-github").unwrap();
        assert_eq!(w.capability, Capability::SessionHostnameProxy);
        assert_eq!(w.support, Support::Untested);
        assert!(w.note.as_deref().unwrap().contains("no TLS interception"));
    }

    fn with_rule(extra: &str) -> Policy {
        let src = format!("{}\n{extra}", include_str!("../../../conformance/policies/home.toml"));
        Policy::parse(&src).unwrap()
    }

    #[test]
    fn proxy_never_covers_ordinary_traffic_or_udp_denies() {
        // hostname deny for ordinary traffic: no session, no proxy, rejected
        let p = with_rule("[[rules]]\nid = \"deny-x\"\naction = \"deny\"\nselector = {}\ndestinations = { hosts = [\"x.example\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        let e = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap_err();
        assert!(e.iter().any(|x| x.message.contains("hostname enforcement")), "{e:?}");
        // session hostname deny on any transport: rejected with the reason
        let p = with_rule("[[rules]]\nid = \"deny-y\"\naction = \"deny\"\nselector = { session = { profiles = [\"coding-session\"] } }\ndestinations = { hosts = [\"y.example\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        let e = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap_err();
        assert!(e.iter().any(|x| x.message.contains("TCP only")), "{e:?}");
        // the same deny restricted to TCP compiles
        let p = with_rule("[[rules]]\nid = \"deny-y\"\naction = \"deny\"\ntransport = \"tcp\"\nselector = { session = { profiles = [\"coding-session\"] } }\ndestinations = { hosts = [\"y.example\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        assert!(compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).is_ok());
        // a session hostname allow on any transport compiles with a TCP-only warning
        let p = with_rule("[[rules]]\nid = \"allow-z\"\naction = \"allow\"\nselector = { session = { profiles = [\"coding-session\"] } }\ndestinations = { hosts = [\"z.example\"] }\nprovenance = { kind = \"git\", reference = \"t\" }\n");
        let s = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap();
        assert!(s.report.warnings.iter().any(|w| w.rule_id == "allow-z" && w.note.as_deref().unwrap().contains("TCP only")));
    }

    // D-PROFILE-CAPABILITY
    #[test]
    fn unsupported_restrictive_profile_fails_compilation() {
        let p =
            with_rule("[[profiles]]\nid = \"browser-lockdown\"\ndefault = \"deny\"\napplies_to = { apps = [{ family = \"firefox\" }] }\n");
        p.validate().unwrap();
        // Linux cannot select apps; the fallback observes, so omitting this deny profile would weaken it
        let e = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap_err();
        assert!(e.iter().any(|x| x.message.contains("browser-lockdown") && x.message.contains("silently fall back")), "{e:?}");
        // macOS can (untested) select apps: compiles, disposition implemented_unproven
        let s = compile(&p, &CapabilityAdvertisement::macos_network_extension(), &opts()).unwrap();
        let it = s.report.items.iter().find(|i| i.item == "profile:browser-lockdown").unwrap();
        assert_eq!(it.disposition, Disposition::ImplementedUnproven);
    }

    #[test]
    fn unsupported_permissive_profile_is_omitted_when_fallback_is_stricter() {
        let mut p =
            with_rule("[[profiles]]\nid = \"browser-open\"\ndefault = \"allow\"\napplies_to = { apps = [{ family = \"firefox\" }] }\n");
        p.profiles.iter_mut().find(|x| x.id == p.fallback_profile.clone()).unwrap().default = DefaultAction::Observe;
        let s = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap();
        let it = s.report.items.iter().find(|i| i.item == "profile:browser-open").unwrap();
        assert_eq!(it.disposition, Disposition::OmittedAccepted);
        assert_eq!(it.missing, vec!["app_enforcement".to_string()]);
        assert!(!it.restrictive);
    }

    #[test]
    fn colliding_backend_ids_fail_linux_compilation() {
        let p = with_rule("[[profiles]]\nid = \"coding.session\"\ndefault = \"allow\"\n");
        let e = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &opts()).unwrap_err();
        assert!(e.iter().any(|x| x.message.contains("same cgroup directory")), "{e:?}");
    }

    #[test]
    fn report_items_never_omit_restrictive_items_as_stricter() {
        for adv in [
            CapabilityAdvertisement::linux_nftables_cgroup(),
            CapabilityAdvertisement::linux_nftables_cgroup_ip_only(),
            CapabilityAdvertisement::macos_network_extension(),
        ] {
            if let Ok(s) = compile(&home(), &adv, &opts()) {
                for it in &s.report.items {
                    let bad = it.restrictive && it.omission == Some(Omission::Stricter);
                    assert!(!bad, "{} omitted as stricter on {}", it.item, adv.adapter);
                }
            }
        }
    }

    #[test]
    fn report_items_satisfy_the_disposition_contract() {
        use crate::contracts::{CapabilityDispositions, Contract};
        for adv in [CapabilityAdvertisement::linux_nftables_cgroup(), CapabilityAdvertisement::macos_network_extension()] {
            let s = compile(&home(), &adv, &opts()).unwrap();
            let d = CapabilityDispositions {
                schema: CapabilityDispositions::SCHEMA.into(),
                device_id: "d1".into(),
                backend: adv.adapter.clone(),
                backend_version: adv.adapter_version.clone(),
                capability_generation: 1,
                cells: vec![],
                policy_digest: Some(format!("sha256:{}", s.policy_digest)),
                items: s.report.items.clone(),
            };
            d.validate().unwrap_or_else(|e| panic!("{}: {e:?}", adv.adapter));
            assert!(!s.report.items.is_empty());
        }
    }
}
