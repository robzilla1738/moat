//! Coverage levels. Weaker coverage is never presented as equivalent protection.
//!
//! Adapted from Digital Kingdom's observer state (`apps/server/src/local-observers.ts` @ e0452c8, Apache-2.0):
//! explicit uncertainty and an append-only history of reporting capability. Moat separates: connected agent,
//! installed filter, applied policy, intact telemetry and independently tested blocking.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::capability::{Capability, CapabilityAdvertisement, Platform, Support};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    /// Activity is visible; nothing is enforced.
    Observed,
    /// Application/user rules are actively enforced.
    Enforced,
    /// A protected session with a tested OS boundary established before launch.
    ProtectedSession,
    /// Only cooperative DNS queries are visible/filtered. No process, transfer or byte claims.
    DnsOnly,
    /// Coverage was expected but something is wrong (filter down, stale, telemetry gap, policy not applied).
    Degraded,
    /// No report.
    Unknown,
}

impl CoverageLevel {
    pub fn label(&self) -> &'static str {
        match self {
            CoverageLevel::Observed => "Observed",
            CoverageLevel::Enforced => "Enforced",
            CoverageLevel::ProtectedSession => "Protected session",
            CoverageLevel::DnsOnly => "DNS-only",
            CoverageLevel::Degraded => "Degraded",
            CoverageLevel::Unknown => "Unknown",
        }
    }
    pub fn claim(&self) -> &'static str {
        match self {
            CoverageLevel::Observed => "Connections are recorded with app attribution where the OS provides it. Traffic is permitted.",
            CoverageLevel::Enforced => "Rules are enforced for supported flows on this device within its declared capabilities.",
            CoverageLevel::ProtectedSession => "This session started inside an OS boundary before launch; its descendants inherit the session policy within tested limits.",
            CoverageLevel::DnsOnly => "Only DNS queries sent to the resolver are visible. Direct-IP and encrypted DNS bypass it. No app, process or byte information.",
            CoverageLevel::Degraded => "Protection is reduced or unverified. See the reason.",
            CoverageLevel::Unknown => "No coverage report has been received.",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EndpointHealth {
    pub agent_connected: bool,
    pub filter_installed: bool,
    pub filter_running: bool,
    pub applied_revision: Option<u64>,
    pub expected_revision: Option<u64>,
    pub telemetry_intact: bool,
    /// An independent canary test confirmed blocking for this revision.
    pub blocking_verified: bool,
    pub enforcing: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CoverageAssessment {
    pub level: CoverageLevel,
    pub reasons: Vec<String>,
    pub verified: bool,
}

pub fn assess(adv: &CapabilityAdvertisement, h: &EndpointHealth, now: DateTime<Utc>, stale_after: Duration) -> CoverageAssessment {
    let mut reasons = Vec::new();
    if adv.platform == Platform::DnsResolver {
        if h.last_seen.map(|t| now - t > stale_after).unwrap_or(true) {
            reasons.push("resolver not reachable recently".into());
            return CoverageAssessment { level: CoverageLevel::Degraded, reasons, verified: false };
        }
        return CoverageAssessment { level: CoverageLevel::DnsOnly, reasons: vec!["cooperative DNS only".into()], verified: false };
    }
    match h.last_seen {
        None => return CoverageAssessment { level: CoverageLevel::Unknown, reasons: vec!["never reported".into()], verified: false },
        Some(t) if now - t > stale_after => reasons.push(format!("last report {} minutes ago", (now - t).num_minutes())),
        _ => {}
    }
    if !h.agent_connected {
        reasons.push("agent not connected".into());
    }
    if !h.filter_installed {
        reasons.push("filter not installed".into());
    } else if !h.filter_running {
        reasons.push("filter installed but not running".into());
    }
    if !h.telemetry_intact {
        reasons.push("telemetry gap reported".into());
    }
    if h.expected_revision.is_some() && h.applied_revision != h.expected_revision {
        reasons.push(format!(
            "policy revision {} not applied (endpoint reports {})",
            h.expected_revision.map(|r| r.to_string()).unwrap_or_default(),
            h.applied_revision.map(|r| r.to_string()).unwrap_or_else(|| "none".into())
        ));
    }
    if !reasons.is_empty() {
        return CoverageAssessment { level: CoverageLevel::Degraded, reasons, verified: false };
    }
    let can_enforce = matches!(adv.support(Capability::AppEnforcement), Support::Supported | Support::Partial | Support::Untested)
        || matches!(adv.support(Capability::UserEnforcement), Support::Supported | Support::Partial | Support::Untested);
    if h.enforcing && can_enforce {
        let mut r = vec![];
        if !h.blocking_verified {
            r.push("blocking not independently verified for this revision".into());
        }
        CoverageAssessment { level: CoverageLevel::Enforced, reasons: r, verified: h.blocking_verified }
    } else {
        CoverageAssessment { level: CoverageLevel::Observed, reasons: vec!["observation mode".into()], verified: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> EndpointHealth {
        EndpointHealth {
            agent_connected: true,
            filter_installed: true,
            filter_running: true,
            applied_revision: Some(4),
            expected_revision: Some(4),
            telemetry_intact: true,
            blocking_verified: false,
            enforcing: true,
            last_seen: Some("2026-10-26T12:00:00Z".parse().unwrap()),
        }
    }
    fn now() -> DateTime<Utc> {
        "2026-10-26T12:01:00Z".parse().unwrap()
    }

    #[test]
    fn enforced_but_unverified() {
        let a = assess(&CapabilityAdvertisement::macos_network_extension(), &healthy(), now(), Duration::minutes(5));
        assert_eq!(a.level, CoverageLevel::Enforced);
        assert!(!a.verified);
    }

    #[test]
    fn degraded_on_problems() {
        let adv = CapabilityAdvertisement::linux_nftables_cgroup();
        let mut h = healthy();
        h.filter_running = false;
        assert_eq!(assess(&adv, &h, now(), Duration::minutes(5)).level, CoverageLevel::Degraded);
        let mut h = healthy();
        h.applied_revision = Some(3);
        assert_eq!(assess(&adv, &h, now(), Duration::minutes(5)).level, CoverageLevel::Degraded);
        let mut h = healthy();
        h.last_seen = Some("2026-10-26T11:00:00Z".parse().unwrap());
        assert_eq!(assess(&adv, &h, now(), Duration::minutes(5)).level, CoverageLevel::Degraded);
    }

    #[test]
    fn dns_is_dns_only() {
        let a = assess(&CapabilityAdvertisement::dns_resolver("adguard-home"), &healthy(), now(), Duration::minutes(5));
        assert_eq!(a.level, CoverageLevel::DnsOnly);
    }

    #[test]
    fn observation_mode() {
        let mut h = healthy();
        h.enforcing = false;
        assert_eq!(
            assess(&CapabilityAdvertisement::macos_network_extension(), &h, now(), Duration::minutes(5)).level,
            CoverageLevel::Observed
        );
    }
}
