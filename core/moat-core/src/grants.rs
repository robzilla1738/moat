//! W03 (core side): exact grants from approval to endpoint.
//!
//! * [`grant_rule`] turns a `moat.grant.v1` into exactly one override rule that keeps every scope field: device
//!   (`selector.devices`), process instance (`selector.processes`, needs process-instance enforcement), task
//!   (`session.session_ids`), executable identity, destination, transport, port and the absolute admission deadline.
//!   A scope the rule language cannot express is refused, never dropped.
//! * [`GrantLedger`] makes issuance idempotent: a retry with the same idempotency key returns the original grant
//!   (original expiry); the same key with a different request is a conflict.
//! * [`effective_digest`] binds the base policy, every overlay grant and the compiler/schema identity into one digest.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::capability::Capability;
use crate::contracts::grant::{DestinationKind, GrantTransport, IssuerRole, MAX_GRANT_SECONDS};
use crate::contracts::{self, format_time, parse_time, Contract, Grant, GrantScope, GrantScopeKind, StreamPolicy};
use crate::net::{PortRange, Transport};
use crate::policy::{
    Action, AppMatcher, Destinations, Layer, OnUnsupported, Policy, ProcessMatch, Provenance, ProvenanceKind, Rule, Selector, SessionMatch,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantError(pub String);

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The override rule a grant becomes. Fails rather than widen: an executable identity that only has a digest, a
/// grant not yet valid at `now`, or an invalid grant are refused.
pub fn grant_rule(g: &Grant, now: DateTime<Utc>) -> Result<Rule, GrantError> {
    g.validate().map_err(|e| GrantError(format!("invalid grant: {e:?}")))?;
    let nb = parse_time(&g.not_before).expect("validated");
    let until = parse_time(&g.admission_until).expect("validated");
    if nb > now {
        // The rule language has no start time; issuing it early would start the permission early.
        return Err(GrantError(format!("grant {} is not valid before {}; refusing to issue it early", g.grant_id, g.not_before)));
    }
    let s: &GrantScope = &g.scope;
    let mut selector = Selector { devices: vec![s.device_id.clone()], ..Default::default() };
    if let Some(e) = &s.executable {
        let m = if e.is_signed() {
            AppMatcher { team_id: e.team_id.clone(), signing_id: e.signing_id.clone(), ..Default::default() }
        } else if let Some(b) = &e.bundle_id {
            AppMatcher { bundle_id: Some(b.clone()), executable: e.path.clone(), ..Default::default() }
        } else if let Some(p) = &e.path {
            AppMatcher { executable: Some(p.clone()), ..Default::default() }
        } else {
            return Err(GrantError("the executable is identified only by digest, which no backend can match yet".into()));
        };
        selector.apps = vec![m];
    }
    match s.kind {
        GrantScopeKind::AppOnDevice => {}
        GrantScopeKind::ProcessInstance => {
            let p = s.process.as_ref().expect("validated");
            let pid = u32::try_from(p.pid).map_err(|_| GrantError("pid out of range".into()))?;
            selector.processes =
                vec![ProcessMatch { boot_id: s.boot_id.clone().expect("validated"), pid, start_generation: p.start_generation }];
        }
        GrantScopeKind::Task => {
            selector.session = Some(SessionMatch { session_ids: vec![s.task_id.clone().expect("validated")], ..Default::default() });
        }
    }
    let destinations = match g.destination.kind {
        DestinationKind::Address => {
            let ip: std::net::IpAddr = g.destination.address.as_deref().expect("validated").parse().expect("validated");
            Destinations { cidrs: vec![IpNet::from(ip)], ..Default::default() }
        }
        DestinationKind::Hostname => Destinations { hosts: vec![g.destination.hostname.clone().expect("validated")], ..Default::default() },
    };
    let mut requires = Vec::new();
    if g.stream_policy == StreamPolicy::TerminateAtDeadline {
        // "Permit an active stream only until a deadline" compiles only where streams can be terminated.
        requires.push(Capability::ExistingFlowRevocation);
    }
    let port = u16::try_from(g.port).map_err(|_| GrantError("port out of range".into()))?;
    Ok(Rule {
        id: g.grant_id.clone(),
        description: g.reason.clone(),
        action: Action::Allow,
        layer: Layer::Override,
        selector,
        destinations,
        transport: match g.transport {
            GrantTransport::Tcp => Transport::Tcp,
            GrantTransport::Udp => Transport::Udp,
        },
        ports: vec![PortRange::single(port)],
        expires_at: Some(until),
        provenance: Provenance {
            kind: ProvenanceKind::OwnerAction,
            reference: Some(format!("grant:{}", g.grant_id)),
            author: Some(g.issuer.principal.clone()),
            audit_ref: Some(format!("approval:{}", g.approval_digest)),
        },
        requires,
        // A grant that a backend cannot enforce exactly is left out with a report: omitting an allow is stricter.
        on_unsupported: OnUnsupported::SkipWithReport,
    })
}

/// The effective policy: base policy plus the grant overlay rules still valid at `now`. Expired grants are dropped
/// here; grants whose base policy digest does not match the base are refused (they were approved against
/// something else).
pub fn apply_grants(base: &Policy, grants: &[Grant], now: DateTime<Utc>) -> Result<Policy, GrantError> {
    let base_digest = format!("sha256:{}", crate::compile::policy_digest(base));
    let mut p = base.clone();
    for g in grants {
        if g.base_policy_digest != base_digest {
            return Err(GrantError(format!(
                "grant {} was approved against {}, not the current base policy {base_digest}",
                g.grant_id, g.base_policy_digest
            )));
        }
        if parse_time(&g.admission_until).is_some_and(|u| u <= now) {
            continue;
        }
        if p.rules.iter().any(|r| r.id == g.grant_id) {
            return Err(GrantError(format!("grant id {} collides with an existing rule id", g.grant_id)));
        }
        p.rules.push(grant_rule(g, now)?);
    }
    p.validate()
        .map_err(|e| GrantError(format!("effective policy invalid: {}", e.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("; "))))?;
    Ok(p)
}

/// Digest binding base policy + overlays + compiler and schema identity (`sha256:` canonical form).
pub fn effective_digest(base: &Policy, grants: &[Grant]) -> String {
    let mut overlays: Vec<String> = grants.iter().map(Grant::authority_digest).collect();
    overlays.sort();
    overlays.dedup();
    contracts::digest_bytes(&contracts::canonical_bytes(&json!({
        "schema": "moat.effective_policy.v1",
        "base_policy_digest": format!("sha256:{}", crate::compile::policy_digest(base)),
        "overlays": overlays,
        "policy_schema": crate::policy::POLICY_SCHEMA,
        "compiler": format!("moat-core {}", env!("CARGO_PKG_VERSION")),
    })))
}

/// What a client asks for. The issuer fills in id, times and digests.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub idempotency_key: String,
    pub scope: GrantScope,
    pub destination: contracts::GrantDestination,
    pub transport: GrantTransport,
    pub port: u64,
    pub ttl_seconds: i64,
    pub stream_policy: StreamPolicy,
    pub approval_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Idempotent issuance. Persist it with serde; it holds the grants it issued, keyed by idempotency key.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantLedger {
    pub by_key: BTreeMap<String, (GrantRequest, Grant)>,
    pub next_serial: u64,
}

impl GrantLedger {
    /// Issue a grant, or return the one already issued for this idempotency key. The original admission deadline
    /// is kept on every retry; a different request under the same key is refused.
    pub fn issue(
        &mut self,
        req: &GrantRequest,
        issuer: &str,
        role: IssuerRole,
        base: &Policy,
        now: DateTime<Utc>,
    ) -> Result<Grant, GrantError> {
        if let Some((orig, g)) = self.by_key.get(&req.idempotency_key) {
            if orig != req {
                return Err(GrantError(format!("idempotency key {} was already used for a different request", req.idempotency_key)));
            }
            return Ok(g.clone());
        }
        if !(1..=MAX_GRANT_SECONDS).contains(&req.ttl_seconds) {
            return Err(GrantError(format!("ttl must be 1..={MAX_GRANT_SECONDS} seconds")));
        }
        let now = parse_time(&format_time(now)).expect("whole seconds");
        self.next_serial += 1;
        let g = Grant {
            schema: Grant::SCHEMA.into(),
            grant_id: format!("grant-{}-{}", now.format("%Y%m%d%H%M%S"), self.next_serial),
            idempotency_key: req.idempotency_key.clone(),
            scope: req.scope.clone(),
            destination: req.destination.clone(),
            transport: req.transport,
            port: req.port,
            issued_at: format_time(now),
            not_before: format_time(now),
            admission_until: format_time(now + Duration::seconds(req.ttl_seconds)),
            stream_policy: req.stream_policy,
            base_policy_digest: format!("sha256:{}", crate::compile::policy_digest(base)),
            issuer: contracts::grant::Issuer { principal: issuer.into(), role, key_id: None },
            approval_digest: req.approval_digest.clone(),
            reason: req.reason.clone(),
        };
        g.validate().map_err(|e| GrantError(format!("{e:?}")))?;
        self.by_key.insert(req.idempotency_key.clone(), (req.clone(), g.clone()));
        Ok(g)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityAdvertisement;
    use crate::compile::{compile, CompileOptions};
    use crate::enrichment::Enricher;
    use crate::eval::{evaluate, EvalContext, FlowAttempt, Verdict};
    use crate::identity::{AppIdentity, ProcessInstanceId};
    use crate::net::{Confidence, HostnameEvidence, HostnameSource};

    fn base() -> Policy {
        Policy::parse(include_str!("../../../conformance/policies/home.toml")).unwrap()
    }
    fn t(s: &str) -> DateTime<Utc> {
        parse_time(s).unwrap()
    }
    fn fixture(name: &str) -> Grant {
        contracts::parse(&std::fs::read_to_string(format!("{}/../../contracts/fixtures/valid/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap())
            .unwrap()
    }
    fn rebased(mut g: Grant) -> Grant {
        g.base_policy_digest = format!("sha256:{}", crate::compile::policy_digest(&base()));
        g
    }
    fn claude_flow(device: &str, pid: Option<(u32, u64)>) -> FlowAttempt {
        FlowAttempt {
            id: "f".into(),
            device_id: device.into(),
            user: Some("robert".into()),
            process: pid.map(|(pid, g)| ProcessInstanceId {
                device_id: device.into(),
                boot_id: "6f1c2a8e-boot".into(),
                pid,
                start_generation: g,
            }),
            app: AppIdentity {
                executable: Some("/Applications/Claude.app/Contents/MacOS/claude".into()),
                team_id: Some("Q6L2SF6YDW".into()),
                signing_id: Some("com.anthropic.claude".into()),
                ..Default::default()
            },
            ancestors: vec![],
            ancestry_complete: true,
            session: None,
            remote_ip: "198.51.100.20".parse().unwrap(),
            remote_port: 443,
            transport: Transport::Tcp,
            hostname: Some(HostnameEvidence {
                name: "api.example.com".into(),
                source: HostnameSource::FlowApi,
                confidence: Confidence::High,
            }),
            at: t("2026-10-27T15:05:00Z"),
        }
    }
    fn deny_everything_else() -> Policy {
        let mut p = base();
        for prof in &mut p.profiles {
            prof.default = crate::policy::DefaultAction::Deny;
            prof.learning = crate::policy::LearningMode::Observe;
        }
        p
    }

    // Acceptance (W03): two devices with the same executable do not share a single-device exception.
    #[test]
    fn same_executable_on_two_devices_does_not_share_a_grant() {
        let b = deny_everything_else();
        let mut g = fixture("grant-app-on-device.json");
        g.base_policy_digest = format!("sha256:{}", crate::compile::policy_digest(&b));
        let eff = apply_grants(&b, &[g], t("2026-10-27T15:01:00Z")).unwrap();
        // survives serialization: the scope is in the policy the endpoint receives
        let wire: Policy = serde_json::from_str(&serde_json::to_string(&eff).unwrap()).unwrap();
        let e = Enricher::new();
        let on_m1 = evaluate(&EvalContext::new(&wire, &e, "mbp-m1"), &claude_flow("mbp-m1", None));
        let on_m2 = evaluate(&EvalContext::new(&wire, &e, "mbp-2"), &claude_flow("mbp-2", None));
        assert_eq!(on_m1.verdict, Verdict::Allow, "{on_m1:?}");
        assert_eq!(on_m2.verdict, Verdict::Deny, "the same signed app on another device is not granted: {on_m2:?}");
        // and through the macOS compiler (app enforcement untested there but expressible)
        let s = compile(
            &wire,
            &CapabilityAdvertisement::macos_network_extension(),
            &CompileOptions { revision: 1, rollback_of: None, issued_at: t("2026-10-27T15:01:00Z"), not_after: None },
        )
        .unwrap();
        let r = s.policy.rules.iter().find(|r| r.id == "grant-01hx").unwrap();
        assert_eq!(r.selector.devices, vec!["mbp-m1".to_string()]);
    }

    // Acceptance (W03): a restarted process cannot reuse an old process grant.
    #[test]
    fn restarted_process_cannot_reuse_a_process_grant() {
        let b = deny_everything_else();
        let mut g = fixture("grant-process-instance.json");
        g.scope.device_id = "mbp-m1".into();
        g.scope.executable = None;
        g.destination =
            contracts::GrantDestination { kind: DestinationKind::Address, address: Some("198.51.100.20".into()), hostname: None };
        g.stream_policy = StreamPolicy::AdmissionOnly;
        g.base_policy_digest = format!("sha256:{}", crate::compile::policy_digest(&b));
        let eff = apply_grants(&b, &[g], t("2026-10-27T15:01:00Z")).unwrap();
        let e = Enricher::new();
        let ctx = EvalContext::new(&eff, &e, "mbp-m1");
        assert_eq!(evaluate(&ctx, &claude_flow("mbp-m1", Some((4242, 918273)))).verdict, Verdict::Allow);
        assert_eq!(evaluate(&ctx, &claude_flow("mbp-m1", Some((4242, 918274)))).verdict, Verdict::Deny, "new start generation");
        assert_eq!(evaluate(&ctx, &claude_flow("mbp-m1", None)).verdict, Verdict::Deny, "no attribution never matches");
        let mut other_boot = claude_flow("mbp-m1", Some((4242, 918273)));
        other_boot.process.as_mut().unwrap().boot_id = "next-boot".into();
        assert_eq!(evaluate(&ctx, &other_boot).verdict, Verdict::Deny, "a reboot ends a process grant");
        // No backend enforces process instances yet: the grant is left out with a report, never widened.
        for adv in [CapabilityAdvertisement::macos_network_extension(), CapabilityAdvertisement::linux_nftables_cgroup()] {
            let s = compile(
                &eff,
                &adv,
                &CompileOptions { revision: 1, rollback_of: None, issued_at: t("2026-10-27T15:01:00Z"), not_after: None },
            )
            .unwrap();
            assert!(s.policy.rules.iter().all(|r| r.id != "grant-01hz"), "{}", adv.adapter);
            assert!(s.report.omitted.iter().any(|o| o.rule_id == "grant-01hz" && o.missing.contains(&Capability::ProcessEnforcement)));
        }
    }

    #[test]
    fn task_grant_is_bound_to_device_and_task() {
        let g = rebased(fixture("grant-task.json"));
        let r = grant_rule(&g, t("2026-10-27T15:01:00Z")).unwrap();
        assert_eq!(r.selector.devices, vec!["arch-desk".to_string()]);
        assert_eq!(r.selector.session.as_ref().unwrap().session_ids, vec!["20261027150000-a1b2c3d4e5f6".to_string()]);
        assert_eq!(r.expires_at, Some(t("2026-10-28T15:00:00Z")));
        assert_eq!(r.transport, Transport::Udp);
        assert_eq!(r.ports, vec![PortRange::single(53)]);
    }

    #[test]
    fn terminate_at_deadline_requires_stream_revocation() {
        let mut g = rebased(fixture("grant-task.json"));
        g.stream_policy = StreamPolicy::TerminateAtDeadline;
        let r = grant_rule(&g, t("2026-10-27T15:01:00Z")).unwrap();
        assert!(r.requires.contains(&Capability::ExistingFlowRevocation));
    }

    #[test]
    fn future_grants_and_foreign_bases_are_refused() {
        let mut g = rebased(fixture("grant-task.json"));
        g.not_before = "2026-10-27T16:00:00Z".into();
        assert!(grant_rule(&g, t("2026-10-27T15:01:00Z")).is_err());
        let g = fixture("grant-task.json"); // approved against another base digest
        assert!(apply_grants(&base(), &[g], t("2026-10-27T15:01:00Z")).is_err());
    }

    #[test]
    fn expired_grants_drop_out_of_the_effective_policy() {
        let g = rebased(fixture("grant-app-on-device.json"));
        let eff = apply_grants(&base(), &[g], t("2026-10-27T15:10:00Z")).unwrap();
        assert!(eff.rules.iter().all(|r| r.id != "grant-01hx"));
    }

    // Acceptance (W03): duplicate/lost requests preserve the original expiry.
    #[test]
    fn retried_request_keeps_the_original_expiry() {
        let mut ledger = GrantLedger::default();
        let req = GrantRequest {
            idempotency_key: "incident-42:allow-once".into(),
            scope: fixture("grant-task.json").scope,
            destination: fixture("grant-task.json").destination,
            transport: GrantTransport::Udp,
            port: 53,
            ttl_seconds: 600,
            stream_policy: StreamPolicy::AdmissionOnly,
            approval_digest: format!("sha256:{}", "2".repeat(64)),
            reason: None,
        };
        let first = ledger.issue(&req, "owner:robert", IssuerRole::Owner, &base(), t("2026-10-27T15:00:00Z")).unwrap();
        let retry = ledger.issue(&req, "owner:robert", IssuerRole::Owner, &base(), t("2026-10-27T15:09:00Z")).unwrap();
        assert_eq!(first, retry, "a retry returns the original grant");
        assert_eq!(retry.admission_until, "2026-10-27T15:10:00Z");
        let mut other = req.clone();
        other.port = 443;
        assert!(ledger.issue(&other, "owner:robert", IssuerRole::Owner, &base(), t("2026-10-27T15:09:00Z")).is_err());
        // the ledger survives serialization (restart) with the same behavior
        let restored: GrantLedger = serde_json::from_str(&serde_json::to_string(&ledger).unwrap()).unwrap();
        let mut restored = restored;
        assert_eq!(restored.issue(&req, "owner:robert", IssuerRole::Owner, &base(), t("2026-10-27T15:30:00Z")).unwrap(), first);
    }

    #[test]
    fn effective_digest_covers_overlays_and_their_scope() {
        let b = base();
        let g1 = rebased(fixture("grant-app-on-device.json"));
        let g2 = rebased(fixture("grant-app-on-device-second-device.json"));
        let none = effective_digest(&b, &[]);
        let one = effective_digest(&b, std::slice::from_ref(&g1));
        let other = effective_digest(&b, std::slice::from_ref(&g2));
        assert_ne!(none, one);
        assert_ne!(one, other, "a grant for another device is a different effective policy");
        assert_eq!(effective_digest(&b, &[g1.clone(), g2.clone()]), effective_digest(&b, &[g2, g1]), "order-independent");
    }
}
