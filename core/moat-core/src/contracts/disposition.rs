//! `moat.capability_dispositions.v1`: what one endpoint can do, per capability cell, and what happened to each
//! profile and rule of a compiled policy (MASTER_ROADMAP §5.2).

use serde::{Deserialize, Serialize};

use super::{cerr, check_digest, check_id, finish, Contract, ContractError};

/// The five dispositions. Consumers must treat any value they do not know as `unknown_degraded` only for display;
/// the schema rejects unknown values so a producer cannot invent a stronger one.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Implemented, installed, and proven on this declared environment (needs an evidence reference).
    SupportedInstalled,
    /// Implemented but not proven on this declared environment.
    ImplementedUnproven,
    /// Not supported; a policy needing it is rejected before activation.
    UnsupportedRejected,
    /// Deliberately left out where omission is permitted (it can only make the endpoint stricter) and its effect
    /// is explicitly accepted.
    OmittedAccepted,
    /// Required runtime evidence is missing, so the endpoint cannot say.
    UnknownDegraded,
}

/// One capability cell: backend mode + subject selector + destination evidence + transport + lifecycle operation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCell {
    /// `moat-core` capability name, e.g. `session_enforcement`.
    pub capability: String,
    /// e.g. `direct`, `session_proxy`.
    pub mode: String,
    /// e.g. `task`, `user`, `app_on_device`, `process_instance`, `device`.
    pub subject: String,
    /// e.g. `ip`, `proxy_hostname`, `sni`, `flow_api_hostname`, `none`.
    pub destination_evidence: String,
    /// `tcp`, `udp` or `any`.
    pub transport: String,
    /// e.g. `admit_new`, `terminate_existing`, `observe`.
    pub lifecycle: String,
    pub disposition: Disposition,
    /// Claim-ledger id or test id backing a `supported_installed` disposition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Why omitting an item is acceptable. Required with `omitted_accepted`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Omission {
    /// Leaving the item out can only make the endpoint stricter (an allow, or a profile whose flows land in an at
    /// least as strict fallback). Never valid for a restrictive item.
    Stricter,
    /// The item's subjects cannot exist on this endpoint (e.g. protected-session rules where sessions are refused
    /// at launch), so omitting it changes no verdict.
    SubjectUnavailable,
}

/// What became of one profile or rule when a policy was compiled for this endpoint.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemDisposition {
    /// `profile:<id>` or `rule:<id>`.
    pub item: String,
    /// True when the item can deny or restrict traffic (deny rules, deny/observe-restricting profiles). A restrictive
    /// item can never be `omitted_accepted`.
    pub restrictive: bool,
    pub disposition: Disposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omission: Option<Omission>,
    /// Capability names the endpoint lacks for this item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDispositions {
    pub schema: String,
    pub device_id: String,
    pub backend: String,
    pub backend_version: String,
    /// Increments whenever the cell set changes (probe downgrade, upgrade).
    pub capability_generation: u64,
    pub cells: Vec<CapabilityCell>,
    /// Present when describing a compiled policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ItemDisposition>,
}

impl Contract for CapabilityDispositions {
    const SCHEMA: &'static str = "moat.capability_dispositions.v1";
    fn validate(&self) -> Result<(), Vec<ContractError>> {
        let mut errs = Vec::new();
        check_id(&self.device_id, "$.device_id", &mut errs);
        check_id(&self.backend, "$.backend", &mut errs);
        if let Some(d) = &self.policy_digest {
            check_digest(d, "$.policy_digest", &mut errs);
        }
        if !self.items.is_empty() && self.policy_digest.is_none() {
            errs.push(cerr("$.policy_digest", "item dispositions describe a compiled policy and need its digest"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for (i, c) in self.cells.iter().enumerate() {
            let key = (&c.capability, &c.mode, &c.subject, &c.destination_evidence, &c.transport, &c.lifecycle);
            if !seen.insert(key) {
                errs.push(cerr(format!("$.cells[{i}]"), "duplicate capability cell"));
            }
            if c.disposition == Disposition::SupportedInstalled && c.evidence_ref.is_none() {
                errs.push(cerr(format!("$.cells[{i}].evidence_ref"), "supported_installed needs an evidence reference"));
            }
            if c.disposition == Disposition::OmittedAccepted {
                errs.push(cerr(format!("$.cells[{i}].disposition"), "omitted_accepted describes policy items, not capabilities"));
            }
            if !matches!(c.transport.as_str(), "tcp" | "udp" | "any") {
                errs.push(cerr(format!("$.cells[{i}].transport"), "transport is tcp, udp or any"));
            }
        }
        let mut items = std::collections::BTreeSet::new();
        for (i, it) in self.items.iter().enumerate() {
            if !(it.item.starts_with("profile:") || it.item.starts_with("rule:")) {
                errs.push(cerr(format!("$.items[{i}].item"), "item is profile:<id> or rule:<id>"));
            }
            if !items.insert(&it.item) {
                errs.push(cerr(format!("$.items[{i}].item"), "duplicate item"));
            }
            match (it.disposition, it.omission) {
                (Disposition::OmittedAccepted, None) => {
                    errs.push(cerr(format!("$.items[{i}].omission"), "omitted_accepted must say why omission is acceptable"))
                }
                (Disposition::OmittedAccepted, Some(Omission::Stricter)) if it.restrictive => errs.push(cerr(
                    format!("$.items[{i}].disposition"),
                    "a restrictive item cannot be omitted as 'stricter': that would silently weaken policy; it must be rejected",
                )),
                (d, Some(_)) if d != Disposition::OmittedAccepted => {
                    errs.push(cerr(format!("$.items[{i}].omission"), "omission only accompanies omitted_accepted"))
                }
                _ => {}
            }
            super::check_sorted_unique(&it.missing, &format!("$.items[{i}].missing"), &mut errs);
            if it.disposition == Disposition::SupportedInstalled && !it.missing.is_empty() {
                errs.push(cerr(format!("$.items[{i}].missing"), "a supported item cannot be missing capabilities"));
            }
        }
        finish(errs)
    }
}
