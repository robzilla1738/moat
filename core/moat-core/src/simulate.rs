//! Simulate a policy change against recorded observations.
//!
//! Replay is a compatibility estimate, not proof that unobserved future traffic is safe. The report says so.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::capability::CapabilityAdvertisement;
use crate::compile::{compile, CompileOptions};
use crate::enrichment::Enricher;
use crate::eval::{evaluate, EvalContext, FlowAttempt, Verdict};
use crate::policy::Policy;

pub const REPLAY_DISCLAIMER: &str =
    "Replay is a compatibility estimate against retained observations. It is not proof that unobserved future traffic is safe.";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChangedFlow {
    pub flow_id: String,
    pub device_id: String,
    pub app: String,
    pub destination: String,
    pub before: String,
    pub after: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PlatformResult {
    pub adapter: String,
    pub compiles: bool,
    pub errors: Vec<String>,
    pub omitted_rules: Vec<String>,
    pub warnings: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct SimulationReport {
    pub observations: usize,
    pub changed: Vec<ChangedFlow>,
    pub newly_blocked: usize,
    pub newly_allowed: usize,
    /// App -> number of affected flows.
    pub affected_apps: BTreeMap<String, usize>,
    /// Flows whose evaluation involved unknown semantics (e.g. hostname rules without hostname evidence).
    pub uncertain: Vec<String>,
    /// Hostnames the proposed allow rules name that never appeared in observations.
    pub unobserved_destinations: Vec<String>,
    pub platforms: Vec<PlatformResult>,
    pub unacknowledged_devices: Vec<String>,
    pub disclaimer: String,
}

fn verdict_label(d: &crate::eval::Decision) -> String {
    match (d.verdict, d.permitted_by_observation) {
        (Verdict::Deny, _) => "blocked".into(),
        (Verdict::Allow, true) => "permitted (observation)".into(),
        (Verdict::Allow, false) => "allowed".into(),
    }
}

pub struct SimulationInput<'a> {
    pub current: &'a Policy,
    pub proposed: &'a Policy,
    pub observations: &'a [FlowAttempt],
    pub enricher: &'a Enricher,
    pub platforms: &'a [CapabilityAdvertisement],
    pub compile_options: CompileOptions,
    /// Devices that have not acknowledged the current revision.
    pub unacknowledged_devices: Vec<String>,
}

pub fn simulate(input: &SimulationInput) -> SimulationReport {
    let mut r = SimulationReport {
        observations: input.observations.len(),
        disclaimer: REPLAY_DISCLAIMER.into(),
        unacknowledged_devices: input.unacknowledged_devices.clone(),
        ..Default::default()
    };
    let mut seen_hosts = BTreeSet::new();
    for f in input.observations {
        if let Some(h) = &f.hostname {
            seen_hosts.insert(crate::net::normalize_host(&h.name));
        }
        let c_old = EvalContext::new(input.current, input.enricher, &f.device_id);
        let c_new = EvalContext::new(input.proposed, input.enricher, &f.device_id);
        let a = evaluate(&c_old, f);
        let b = evaluate(&c_new, f);
        let (la, lb) = (verdict_label(&a), verdict_label(&b));
        if b.notes.iter().any(|n| n.contains("no hostname evidence") || n.contains("incomplete")) {
            r.uncertain.push(f.id.clone());
        }
        if la != lb {
            if b.verdict == Verdict::Deny && a.verdict == Verdict::Allow {
                r.newly_blocked += 1;
            }
            if b.verdict == Verdict::Allow && a.verdict == Verdict::Deny {
                r.newly_allowed += 1;
            }
            let app = f.app.display();
            *r.affected_apps.entry(app.clone()).or_default() += 1;
            r.changed.push(ChangedFlow {
                flow_id: f.id.clone(),
                device_id: f.device_id.clone(),
                app,
                destination: f.hostname.as_ref().map(|h| h.name.clone()).unwrap_or_else(|| f.remote_ip.to_string())
                    + &format!(":{}", f.remote_port),
                before: la,
                after: lb,
            });
        }
    }
    let mut unobserved = BTreeSet::new();
    for rule in input.proposed.rules.iter().filter(|r| r.action == crate::policy::Action::Allow) {
        let mut hosts: Vec<&String> = rule.destinations.hosts.iter().collect();
        for s in &rule.destinations.sets {
            if let Some(set) = input.proposed.destination_sets.get(s) {
                hosts.extend(set.destinations.hosts.iter());
            }
        }
        for h in hosts {
            let observed = seen_hosts.iter().any(|s| crate::net::host_matches(h, s));
            if !observed {
                unobserved.insert(h.clone());
            }
        }
    }
    r.unobserved_destinations = unobserved.into_iter().collect();
    for adv in input.platforms {
        match compile(input.proposed, adv, &input.compile_options) {
            Ok(s) => r.platforms.push(PlatformResult {
                adapter: adv.adapter.clone(),
                compiles: true,
                errors: vec![],
                omitted_rules: s.report.omitted.iter().map(|o| o.rule_id.clone()).collect(),
                warnings: s.report.warnings.len(),
            }),
            Err(e) => r.platforms.push(PlatformResult {
                adapter: adv.adapter.clone(),
                compiles: false,
                errors: e.iter().map(|x| x.to_string()).collect(),
                omitted_rules: vec![],
                warnings: 0,
            }),
        }
    }
    r.uncertain.dedup();
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::tests::{flow, policy};
    use crate::policy::DefaultAction;

    #[test]
    fn tightening_ordinary_profile_reports_newly_blocked() {
        let cur = policy();
        let mut prop = policy();
        prop.profiles.iter_mut().find(|p| p.id == "ordinary-desktop-learning").unwrap().default = DefaultAction::Deny;
        let obs = vec![
            flow("safari", "198.51.100.1", 443, Some("example.com"), None),
            flow("git", "198.51.100.2", 443, Some("api.github.com"), Some("coding-session")),
        ];
        let e = Enricher::new();
        let r = simulate(&SimulationInput {
            current: &cur,
            proposed: &prop,
            observations: &obs,
            enricher: &e,
            platforms: &[CapabilityAdvertisement::macos_network_extension(), CapabilityAdvertisement::linux_nftables_cgroup()],
            compile_options: CompileOptions {
                target_devices: vec![],
                revision: 1,
                rollback_of: None,
                issued_at: "2026-10-26T12:00:00Z".parse().unwrap(),
                not_after: None,
            },
            unacknowledged_devices: vec!["mini".into()],
        });
        assert_eq!(r.newly_blocked, 1);
        assert_eq!(r.changed[0].app, "safari");
        assert!(r.platforms.iter().all(|p| p.compiles));
        assert!(r.unobserved_destinations.contains(&"registry.npmjs.org".to_string()));
        assert!(r.disclaimer.contains("estimate"));
    }
}
