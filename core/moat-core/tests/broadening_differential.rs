//! W02 differential test: hunt for a denied→permitted counterexample the diff failed to call broadening.
//!
//! Random small policies over a closed universe (two apps, a protected-session profile, three addresses, two
//! hostnames, two ports, two transports, three points in time) are mutated with random edits. Whenever the diff says
//! "not broadening", every flow in the universe is evaluated against both policies at every time point; a flow that
//! the old policy denied and the new one permits (allow or observe) is a classifier bug.

use chrono::{DateTime, Duration, Utc};
use moat_core::diff::diff;
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, EvalContext, FlowAttempt, Verdict};
use moat_core::identity::{AppIdentity, Boundary, SessionRef};
use moat_core::net::{Confidence, HostnameEvidence, HostnameSource, NetScope, PortRange, Transport};
use moat_core::policy::*;
use proptest::prelude::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

fn t0() -> DateTime<Utc> {
    "2026-10-27T12:00:00Z".parse().unwrap()
}
fn times() -> [DateTime<Utc>; 3] {
    [t0(), t0() + Duration::hours(2), t0() + Duration::hours(6)]
}
fn expiries() -> [Option<DateTime<Utc>>; 3] {
    [None, Some(t0() + Duration::hours(1)), Some(t0() + Duration::hours(4))]
}

fn app(f: &str) -> AppMatcher {
    AppMatcher { family: Some(f.into()), ..Default::default() }
}

fn gen_selector(r: &mut Rng) -> Selector {
    match r.pick(6) {
        0 => Selector::default(),
        1 => Selector { apps: vec![app("alpha")], ..Default::default() },
        2 => Selector { apps: vec![app("beta")], ..Default::default() },
        3 => Selector { apps: vec![app("alpha"), app("beta")], ..Default::default() },
        4 => Selector { session: Some(SessionMatch { profiles: vec!["sess".into()], ..Default::default() }), ..Default::default() },
        _ => Selector { session: Some(SessionMatch { session_ids: vec!["s1".into()], ..Default::default() }), ..Default::default() },
    }
}

fn gen_dest(r: &mut Rng) -> Destinations {
    match r.pick(7) {
        0 => Destinations { cidrs: vec!["10.1.0.1/32".parse().unwrap()], ..Default::default() },
        1 => Destinations { cidrs: vec!["10.1.0.0/30".parse().unwrap()], ..Default::default() },
        2 => Destinations { hosts: vec!["x.example".into()], ..Default::default() },
        3 => Destinations { sets: vec!["S".into()], ..Default::default() },
        4 => Destinations { any: true, ..Default::default() },
        5 => Destinations { scopes: vec![NetScope::Public], ..Default::default() },
        _ => Destinations { hosts: vec!["x.example".into(), "y.example".into()], ..Default::default() },
    }
}

fn gen_rule(r: &mut Rng, id: String) -> Rule {
    let action = if r.coin() { Action::Allow } else { Action::Deny };
    let mut selector = gen_selector(r);
    let mut expires_at = expiries()[r.pick(3)];
    let mut layer = Layer::Explicit;
    let mut provenance = Provenance { kind: ProvenanceKind::Git, reference: Some("t".into()), author: None, audit_ref: None };
    match (action, r.pick(4)) {
        (Action::Deny, 0) => layer = Layer::Emergency,
        (Action::Deny, 1) => {
            layer = Layer::Safety;
            expires_at = None;
        }
        (Action::Allow, 0) => {
            layer = Layer::Override;
            if !selector.is_narrow() {
                selector = Selector { apps: vec![app("alpha")], ..Default::default() };
            }
            expires_at = Some(expiries()[1 + r.pick(2)].unwrap());
            provenance = Provenance { kind: ProvenanceKind::OwnerAction, reference: None, author: None, audit_ref: Some("a1".into()) };
        }
        _ => {}
    }
    if selector.session.as_ref().is_some_and(|s| !s.session_ids.is_empty()) && (action != Action::Allow || expires_at.is_none()) {
        selector = Selector { session: Some(SessionMatch { profiles: vec!["sess".into()], ..Default::default() }), ..Default::default() };
    }
    Rule {
        id,
        description: None,
        action,
        layer,
        selector,
        destinations: gen_dest(r),
        transport: [Transport::Any, Transport::Tcp, Transport::Udp][r.pick(3)],
        ports: [vec![], vec![PortRange::single(443)], vec!["400-500".parse().unwrap()]][r.pick(3)].clone(),
        expires_at,
        provenance,
        requires: vec![],
        on_unsupported: OnUnsupported::Reject,
    }
}

fn defaults(r: &mut Rng) -> DefaultAction {
    [DefaultAction::Deny, DefaultAction::Observe, DefaultAction::Allow][r.pick(3)]
}

fn gen_policy(r: &mut Rng) -> Policy {
    let mut profiles = vec![
        Profile {
            id: "fb".into(),
            description: None,
            default: defaults(r),
            learning: LearningMode::Observe,
            applies_to: Selector::default(),
        },
        Profile {
            id: "sess".into(),
            description: None,
            default: DefaultAction::Deny,
            learning: LearningMode::Observe,
            applies_to: Selector::default(),
        },
    ];
    if r.coin() {
        profiles.push(Profile {
            id: "pa".into(),
            description: None,
            default: defaults(r),
            learning: LearningMode::Observe,
            applies_to: Selector { apps: vec![app("alpha")], ..Default::default() },
        });
    }
    if r.coin() {
        profiles.push(Profile {
            id: "pab".into(),
            description: None,
            default: defaults(r),
            learning: LearningMode::Observe,
            applies_to: Selector { apps: vec![app("alpha"), app("beta")], ..Default::default() },
        });
    }
    if r.coin() {
        let l = profiles.len();
        profiles.swap(2.min(l - 1), l - 1);
    }
    let mut sets = std::collections::BTreeMap::new();
    let set_dest = match r.pick(3) {
        0 => Destinations { cidrs: vec!["10.1.0.2/32".parse().unwrap()], ..Default::default() },
        1 => Destinations { hosts: vec!["y.example".into()], ..Default::default() },
        _ => Destinations { cidrs: vec!["10.1.0.2/32".parse().unwrap()], hosts: vec!["x.example".into()], ..Default::default() },
    };
    sets.insert("S".to_string(), DestinationSet { description: None, destinations: set_dest });
    let n = r.pick(5);
    Policy {
        schema: POLICY_SCHEMA.into(),
        name: "diff-prop".into(),
        description: None,
        device_groups: Default::default(),
        destination_sets: sets,
        profiles,
        rules: (0..n).map(|i| gen_rule(r, format!("r{i}"))).collect(),
        fallback_profile: "fb".into(),
    }
}

fn mutate(r: &mut Rng, p: &mut Policy) {
    match r.pick(14) {
        0 => {
            let id = format!("n{}", r.next() % 1000);
            let rule = gen_rule(r, id);
            p.rules.push(rule);
        }
        1 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules.remove(i);
        }
        2 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules[i].expires_at = expiries()[r.pick(3)];
        }
        3 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules[i].destinations = gen_dest(r);
        }
        4 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules[i].selector = gen_selector(r);
        }
        5 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules[i].ports = [vec![], vec![PortRange::single(443)], vec!["400-500".parse().unwrap()]][r.pick(3)].clone();
        }
        6 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules[i].transport = [Transport::Any, Transport::Tcp, Transport::Udp][r.pick(3)];
        }
        7 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules[i].action = if p.rules[i].action == Action::Allow { Action::Deny } else { Action::Allow };
        }
        8 if !p.rules.is_empty() => {
            let i = r.pick(p.rules.len());
            p.rules[i].layer = [Layer::Safety, Layer::Emergency, Layer::Override, Layer::Explicit][r.pick(4)];
        }
        9 if p.profiles.len() > 2 => {
            let a = r.pick(p.profiles.len());
            let b = r.pick(p.profiles.len());
            p.profiles.swap(a, b);
        }
        10 => {
            let i = r.pick(p.profiles.len());
            p.profiles[i].default = defaults(r);
        }
        11 => {
            let s = p.destination_sets.get_mut("S").unwrap();
            match r.pick(3) {
                0 => s.destinations.hosts.push("x.example".into()),
                1 => s.destinations.cidrs.clear(),
                _ => s.destinations.cidrs.push("203.0.113.0/24".parse().unwrap()),
            }
        }
        12 if p.profiles.len() > 2 => {
            let i = 2 + r.pick(p.profiles.len() - 2);
            p.profiles[i].applies_to = gen_selector(r);
        }
        13 if p.rules.len() > 1 => {
            let a = r.pick(p.rules.len());
            let b = r.pick(p.rules.len());
            p.rules.swap(a, b);
        }
        _ => {
            let i = r.pick(p.profiles.len());
            p.profiles[i].description = Some("edited".into());
        }
    }
}

fn flows() -> Vec<FlowAttempt> {
    let mut out = Vec::new();
    let sessions = [None, Some("s1"), Some("s2")];
    for fam in ["alpha", "beta", "gamma"] {
        for sess in sessions {
            for ip in ["10.1.0.1", "10.1.0.2", "203.0.113.5"] {
                for host in [None, Some("x.example"), Some("y.example")] {
                    for port in [443u16, 80] {
                        for transport in [Transport::Tcp, Transport::Udp] {
                            out.push(FlowAttempt {
                                id: "f".into(),
                                device_id: "d1".into(),
                                user: Some("u".into()),
                                process: None,
                                app: AppIdentity {
                                    family: Some(fam.into()),
                                    executable: Some(format!("/usr/bin/{fam}")),
                                    ..Default::default()
                                },
                                ancestors: vec![],
                                ancestry_complete: true,
                                session: sess.map(|id| SessionRef {
                                    id: id.into(),
                                    profile: "sess".into(),
                                    boundary: Boundary::LinuxCgroup,
                                    verified: true,
                                }),
                                remote_ip: ip.parse().unwrap(),
                                remote_port: port,
                                transport,
                                hostname: host.map(|h| HostnameEvidence {
                                    name: h.into(),
                                    source: HostnameSource::Sni,
                                    confidence: Confidence::High,
                                }),
                                at: t0(),
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

fn counterexample(old: &Policy, new: &Policy, flows: &[FlowAttempt]) -> Option<String> {
    let e = Enricher::new();
    let co = EvalContext::new(old, &e, "d1");
    let cn = EvalContext::new(new, &e, "d1");
    for at in times() {
        for f in flows {
            let mut f = f.clone();
            f.at = at;
            let a = evaluate(&co, &f);
            let b = evaluate(&cn, &f);
            if a.verdict == Verdict::Deny && b.verdict == Verdict::Allow {
                return Some(format!(
                    "flow {:?} at {at}: old {} / new {}",
                    (
                        &f.app.family,
                        &f.session.as_ref().map(|s| &s.id),
                        f.remote_ip,
                        &f.hostname.as_ref().map(|h| &h.name),
                        f.remote_port,
                        f.transport
                    ),
                    a.summary(),
                    b.summary()
                ));
            }
        }
    }
    None
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]
    #[test]
    fn non_broadening_diffs_permit_nothing_new(seed in any::<u64>(), edits in 1usize..4) {
        let mut r = Rng(seed | 1);
        let old = gen_policy(&mut r);
        prop_assume!(old.validate().is_ok());
        let mut new = old.clone();
        for _ in 0..edits {
            mutate(&mut r, &mut new);
        }
        prop_assume!(new.validate().is_ok());
        let d = diff(&old, &new);
        if !d.is_broadening() {
            let fl = flows();
            if let Some(c) = counterexample(&old, &new, &fl) {
                prop_assert!(false, "diff missed broadening: {c}\nbroadening: {:?}\nold: {}\nnew: {}", d.broadening,
                    serde_json::to_string(&old).unwrap(), serde_json::to_string(&new).unwrap());
            }
        }
    }
}

/// The generator must actually exercise both outcomes, or the property above proves nothing.
#[test]
fn generator_produces_both_broadening_and_safe_changes() {
    let (mut broad, mut safe) = (0, 0);
    for seed in 1..400u64 {
        let mut r = Rng((seed * 7919) | 1);
        let old = gen_policy(&mut r);
        if old.validate().is_err() {
            continue;
        }
        let mut new = old.clone();
        mutate(&mut r, &mut new);
        if new.validate().is_err() {
            continue;
        }
        if diff(&old, &new).is_broadening() {
            broad += 1;
        } else {
            safe += 1;
        }
    }
    assert!(broad > 40 && safe > 40, "broadening {broad}, safe {safe}");
}
