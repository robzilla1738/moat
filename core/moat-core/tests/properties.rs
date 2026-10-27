//! Property tests for precedence, signing, host matching and diffing.

use chrono::{DateTime, Utc};
use moat_core::compile::{compile, CompileOptions};
use moat_core::diff::diff;
use moat_core::enrichment::Enricher;
use moat_core::eval::{evaluate, EvalContext, FlowAttempt, Verdict};
use moat_core::identity::AppIdentity;
use moat_core::net::{classify, host_matches, PortRange, Transport};
use moat_core::policy::*;
use moat_core::signing::{generate_key, sign_snapshot, verify_snapshot, TrustStore, VerifyError};
use moat_core::{CapabilityAdvertisement, Platform};
use proptest::prelude::*;

fn t() -> DateTime<Utc> {
    "2026-10-26T12:00:00Z".parse().unwrap()
}

fn base_policy(rules: Vec<Rule>) -> Policy {
    Policy {
        schema: POLICY_SCHEMA.into(),
        name: "prop".into(),
        description: None,
        device_groups: Default::default(),
        destination_sets: Default::default(),
        profiles: vec![Profile { id: "p".into(), description: None, default: DefaultAction::Observe, learning: LearningMode::Observe, applies_to: Selector::default() }],
        rules,
        fallback_profile: "p".into(),
    }
}

fn rule(i: usize, action: Action, layer: Layer, any: bool) -> Rule {
    let narrow = Selector { apps: vec![AppMatcher { family: Some("x".into()), ..Default::default() }], ..Default::default() };
    Rule {
        id: format!("r{i}"),
        description: None,
        action,
        layer,
        selector: if layer == Layer::Override { narrow } else { Selector::default() },
        destinations: if any { Destinations { any: true, ..Default::default() } } else { Destinations { scopes: vec![moat_core::net::NetScope::Public], ..Default::default() } },
        transport: Transport::Any,
        ports: vec![],
        expires_at: if layer == Layer::Override { Some("2027-01-01T00:00:00Z".parse().unwrap()) } else { None },
        provenance: Provenance {
            kind: if layer == Layer::Override { ProvenanceKind::OwnerAction } else { ProvenanceKind::Git },
            reference: None,
            author: None,
            audit_ref: if layer == Layer::Override { Some("audit-1".into()) } else { None },
        },
        requires: vec![],
        on_unsupported: OnUnsupported::Reject,
    }
}

fn flow() -> FlowAttempt {
    FlowAttempt {
        id: "f".into(),
        device_id: "d".into(),
        user: None,
        process: None,
        app: AppIdentity { family: Some("x".into()), ..Default::default() },
        ancestors: vec![],
        ancestry_complete: true,
        session: None,
        remote_ip: "198.51.100.1".parse().unwrap(),
        remote_port: 443,
        transport: Transport::Tcp,
        hostname: None,
        at: t(),
    }
}

fn arb_rule() -> impl Strategy<Value = (Action, Layer)> {
    prop_oneof![
        Just((Action::Deny, Layer::Safety)),
        Just((Action::Allow, Layer::Safety)),
        Just((Action::Deny, Layer::Emergency)),
        Just((Action::Allow, Layer::Override)),
        Just((Action::Deny, Layer::Explicit)),
        Just((Action::Allow, Layer::Explicit)),
    ]
}

proptest! {
    /// The verdict always equals the expected precedence outcome computed independently.
    #[test]
    fn precedence_is_total_and_ordered(specs in proptest::collection::vec(arb_rule(), 0..8)) {
        let rules: Vec<Rule> = specs.iter().enumerate().map(|(i, (a, l))| rule(i, *a, *l, i % 2 == 0)).collect();
        let p = base_policy(rules);
        prop_assert!(p.validate().is_ok(), "{:?}", p.validate());
        let e = Enricher::new();
        let d = evaluate(&EvalContext::new(&p, &e, "d"), &flow());
        // independent oracle
        let expected = (0..4u8).find_map(|rank| {
            let at: Vec<&(Action, Layer)> = specs.iter().filter(|(_, l)| l.rank() == rank).collect();
            if at.is_empty() { None } else if at.iter().any(|(a, _)| *a == Action::Deny) { Some(Verdict::Deny) } else { Some(Verdict::Allow) }
        }).unwrap_or(Verdict::Allow);
        prop_assert_eq!(d.verdict, expected);
        prop_assert_eq!(d.overridden.len(), specs.len().saturating_sub(1));
    }

    /// Adding an explicit allow never reverses an emergency or safety deny.
    #[test]
    fn narrow_allow_never_beats_higher_deny(higher in prop_oneof![Just(Layer::Safety), Just(Layer::Emergency)]) {
        let p = base_policy(vec![rule(0, Action::Deny, higher, true), rule(1, Action::Allow, Layer::Explicit, true), rule(2, Action::Allow, Layer::Override, true)]);
        let e = Enricher::new();
        let d = evaluate(&EvalContext::new(&p, &e, "d"), &flow());
        prop_assert_eq!(d.verdict, Verdict::Deny);
    }

    #[test]
    fn replay_is_always_rejected(applied in 1u64..1000, offset in 0u64..1000) {
        let k = generate_key();
        let mut trust = TrustStore::new();
        trust.trust(k.verifying_key());
        let p = base_policy(vec![]);
        let rev = applied.saturating_sub(offset).max(1);
        let s = compile(&p, &CapabilityAdvertisement::linux_nftables_cgroup(), &CompileOptions { revision: rev, rollback_of: None, issued_at: t(), not_after: None }).unwrap();
        let signed = sign_snapshot(&s, &k);
        let r = verify_snapshot(&signed, &trust, Platform::Linux, Some(applied), t());
        let is_replay = matches!(r, Err(VerifyError::Replay { .. }));
        prop_assert!(is_replay);
        let ok = verify_snapshot(&signed, &trust, Platform::Linux, Some(rev - 1), t());
        prop_assert!(ok.is_ok());
    }

    #[test]
    fn wildcard_never_matches_apex(label in "[a-z]{1,10}", apex in "[a-z]{1,10}\\.(com|net|io)") {
        let pat = format!("*.{apex}");
        prop_assert!(!host_matches(&pat, &apex));
        let sub = format!("{label}.{apex}");
        let upper = sub.to_uppercase();
        prop_assert!(host_matches(&pat, &sub));
        prop_assert!(host_matches(&pat, &upper));
        let glued = format!("{label}{apex}");
        prop_assert!(!host_matches(&pat, &glued));
    }

    #[test]
    fn port_range_roundtrip(a in 0u16..=65535, b in 0u16..=65535) {
        let (s, e) = if a <= b { (a, b) } else { (b, a) };
        let r = PortRange { start: s, end: e };
        let j = serde_json::to_string(&r).unwrap();
        let back: PortRange = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(r, back);
    }

    #[test]
    fn classify_never_panics(bytes in proptest::array::uniform16(any::<u8>()), v4 in any::<u32>()) {
        let _ = classify(std::net::IpAddr::from(bytes));
        let _ = classify(std::net::IpAddr::from(v4.to_be_bytes()));
    }

    #[test]
    fn adding_any_allow_is_broadening(n in 0usize..5) {
        let old = base_policy((0..n).map(|i| rule(i, Action::Deny, Layer::Explicit, true)).collect());
        let mut new = old.clone();
        new.rules.push(rule(99, Action::Allow, Layer::Explicit, true));
        prop_assert!(diff(&old, &new).is_broadening());
        prop_assert!(diff(&old, &old).is_empty());
    }
}
