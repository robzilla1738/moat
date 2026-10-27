//! `moat.event.v1`: the event envelope and evidence vocabulary (MASTER_ROADMAP §5.3).
//!
//! Evidence stages stay distinct: requested → authorized → compiled → delivered → received → activated →
//! independently_checked. Every event names its producer and the authority that producer holds, its device, boot
//! and sequence, event and ingestion times with clock uncertainty, and — where relevant — subject identities with
//! confidence, destination evidence, generations, the decision with its matching/overridden rules, measurements
//! with scope and source, and coverage/gap markers.

use serde::{Deserialize, Serialize};

use super::grant::valid_hostname;
use super::subject::Subject;
use super::{cerr, check_id, check_time, finish, Contract, ContractError};
use crate::authority::{check as authority_check, Assertion, Origin};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStage {
    Requested,
    Authorized,
    Compiled,
    Delivered,
    Received,
    Activated,
    IndependentlyChecked,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A policy/grant lifecycle step; carries `stage`.
    Lifecycle,
    /// A connection decision at the enforcement point; carries `decision` and `destination`.
    FlowDecision,
    /// Evidence was lost; carries `gap`.
    Gap,
    /// The producer restarted; sequence numbering restarts only with a new boot or this marker.
    Restart,
    /// Coverage changed (sensor stopped, capability downgraded, isolation entered/left); carries `coverage`.
    CoverageChange,
    /// A task (protected session) started or ended.
    TaskLifecycle,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HostnameSource {
    FlowApi,
    ConnectProxy,
    Sni,
    HttpHost,
    DnsAnswer,
    Inferred,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostnameEvidence {
    pub name: String,
    pub source: HostnameSource,
    pub confidence: Confidence,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventDestination {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u64>,
    /// `tcp`, `udp`, `other`.
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<HostnameEvidence>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Generations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_generation: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventDecision {
    /// `allow`, `deny`, `observe` (permitted, not enforced).
    pub verdict: String,
    /// `rule:<id>` or `profile_default:<id>`.
    pub winner: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overridden: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    pub name: String,
    pub value: u64,
    pub unit: String,
    /// What the number covers: `flow`, `rule_counter`, `conversation_window`, `task`.
    pub scope: String,
    /// Who measured it, e.g. `nftables_counter`, `nefilter_report`, `proxy`.
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    /// What was lost: `events`, `sequence`, `attribution`, `quota_pruned`.
    pub scope: String,
    /// Number of lost items when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_sequence: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema: String,
    pub event_id: String,
    pub kind: EventKind,
    pub producer: String,
    /// The authority the producer holds; checked against what the event asserts.
    pub authority: Origin,
    pub device_id: String,
    pub boot_id: String,
    pub sequence: u64,
    pub event_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_time: Option<String>,
    pub clock_uncertainty_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<EvidenceStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    /// Confidence in the subject attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_confidence: Option<Confidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<EventDestination>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generations: Option<Generations>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<EventDecision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub measurements: Vec<Measurement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap: Option<Gap>,
    /// e.g. `enforced`, `observe_only`, `degraded`, `isolated`, `unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    /// Producer-specific detail. Never read for authorization or status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Map<String, serde_json::Value>>,
}

impl Event {
    /// The assertion this event makes, for the producer-authority check.
    pub fn assertion(&self) -> Option<Assertion> {
        Some(match (self.kind, self.stage, self.decision.as_ref().map(|d| d.verdict.as_str())) {
            (EventKind::Lifecycle, Some(EvidenceStage::Received), _) => Assertion::PolicyReceived,
            (EventKind::Lifecycle, Some(EvidenceStage::Activated), _) => Assertion::PolicyApplied,
            (EventKind::Lifecycle, Some(EvidenceStage::IndependentlyChecked), _) => Assertion::EffectVerified,
            // requested/authorized/compiled/delivered are controller/signer facts recorded in their audit log, not
            // assertions any endpoint-side producer may make.
            (EventKind::Lifecycle, _, _) => return None,
            (EventKind::FlowDecision, _, Some("deny")) => Assertion::ConnectionBlocked,
            (EventKind::FlowDecision, _, Some("allow")) => Assertion::ConnectionAllowed,
            (EventKind::FlowDecision, _, _) => Assertion::ConnectionObserved,
            (EventKind::Gap | EventKind::Restart | EventKind::CoverageChange, _, _) => Assertion::CoverageChange,
            (EventKind::TaskLifecycle, _, _) => Assertion::SessionLifecycle,
        })
    }
}

impl Contract for Event {
    const SCHEMA: &'static str = "moat.event.v1";
    fn validate(&self) -> Result<(), Vec<ContractError>> {
        let mut errs = Vec::new();
        check_id(&self.event_id, "$.event_id", &mut errs);
        check_id(&self.producer, "$.producer", &mut errs);
        check_id(&self.device_id, "$.device_id", &mut errs);
        check_id(&self.boot_id, "$.boot_id", &mut errs);
        check_time(&self.event_time, "$.event_time", &mut errs);
        if let Some(t) = &self.ingest_time {
            check_time(t, "$.ingest_time", &mut errs);
        }
        let need = |ok: bool, field: &str, errs: &mut Vec<ContractError>| {
            if !ok {
                errs.push(cerr(format!("$.{field}"), format!("required for kind {:?}", self.kind)));
            }
        };
        match self.kind {
            EventKind::Lifecycle => need(self.stage.is_some(), "stage", &mut errs),
            EventKind::FlowDecision => {
                need(self.decision.is_some(), "decision", &mut errs);
                need(self.destination.is_some(), "destination", &mut errs);
            }
            EventKind::Gap => need(self.gap.is_some(), "gap", &mut errs),
            EventKind::CoverageChange => need(self.coverage.is_some(), "coverage", &mut errs),
            EventKind::Restart | EventKind::TaskLifecycle => {}
        }
        if self.kind != EventKind::Lifecycle && self.stage.is_some() {
            errs.push(cerr("$.stage", "only lifecycle events carry a stage"));
        }
        if let Some(s) = &self.subject {
            if s.schema != <Subject as Contract>::SCHEMA {
                errs.push(cerr("$.subject.schema", "embedded subject must be moat.subject.v1"));
            }
            s.check("$.subject", &mut errs);
            if s.device_id != self.device_id {
                errs.push(cerr("$.subject.device_id", "subject device differs from the event device"));
            }
            if self.subject_confidence.is_none() {
                errs.push(cerr("$.subject_confidence", "a subject carries its attribution confidence"));
            }
        }
        if let Some(d) = &self.destination {
            if !matches!(d.transport.as_str(), "tcp" | "udp" | "other") {
                errs.push(cerr("$.destination.transport", "transport is tcp, udp or other"));
            }
            if let Some(a) = &d.address {
                if a.parse::<std::net::IpAddr>().map(|ip| ip.to_string() != *a).unwrap_or(true) {
                    errs.push(cerr("$.destination.address", "canonical IP address text required"));
                }
            }
            if d.port.is_some_and(|p| p == 0 || p > 65535) {
                errs.push(cerr("$.destination.port", "port must be 1-65535"));
            }
            if let Some(h) = &d.hostname {
                if !valid_hostname(&h.name) {
                    errs.push(cerr("$.destination.hostname.name", "invalid hostname"));
                }
            }
        }
        if let Some(dec) = &self.decision {
            if !matches!(dec.verdict.as_str(), "allow" | "deny" | "observe") {
                errs.push(cerr("$.decision.verdict", "verdict is allow, deny or observe"));
            }
            if !(dec.winner.starts_with("rule:") || dec.winner.starts_with("profile_default:")) {
                errs.push(cerr("$.decision.winner", "winner is rule:<id> or profile_default:<id>"));
            }
        }
        for (i, m) in self.measurements.iter().enumerate() {
            if !matches!(m.scope.as_str(), "flow" | "rule_counter" | "conversation_window" | "task") {
                errs.push(cerr(format!("$.measurements[{i}].scope"), "scope is flow, rule_counter, conversation_window or task"));
            }
        }
        if let Some(g) = &self.gap {
            if let (Some(a), Some(b)) = (g.from_sequence, g.to_sequence) {
                if a > b {
                    errs.push(cerr("$.gap", "from_sequence after to_sequence"));
                }
            }
        }
        if let Some(a) = self.assertion() {
            if let Err(v) = authority_check(self.authority, a) {
                errs.push(cerr("$.authority", v.detail));
            }
        }
        finish(errs)
    }
}
