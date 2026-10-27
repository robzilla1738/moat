//! Capability contracts.
//!
//! Every endpoint adapter advertises the concrete capabilities it actually has. A policy that needs a
//! capability the target platform does not have fails validation: it is never silently compiled into a
//! weaker rule (roadmap §5, "Capability contracts and failure behavior").

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A concrete thing an endpoint can (or cannot) do.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Attribute a connection to a specific process instance (not just a PID).
    ProcessIdentity,
    /// Attribute a connection to the chain of ancestors that launched the process.
    AncestorAttribution,
    /// Enforce per-application rules (block/allow by app identity).
    AppEnforcement,
    /// Enforce rules for a protected session established before launch.
    SessionEnforcement,
    /// Enforce rules per OS user.
    UserEnforcement,
    /// Record DNS answers as hostname evidence.
    DnsEvidence,
    /// Enforce rules keyed by hostname (not only IP).
    HostnameEnforcement,
    /// Report byte counters with stated scope.
    ByteCounters,
    /// Stop flows that were already established when a rule changed.
    ExistingFlowRevocation,
    /// Detect and report telemetry loss (sequence numbers, gap markers).
    TelemetryCompleteness,
    /// Enforce IPv6 traffic, not just IPv4.
    Ipv6Enforcement,
    /// Enforce UDP (including QUIC), not just TCP.
    UdpEnforcement,
}

impl Capability {
    pub const ALL: [Capability; 12] = [
        Capability::ProcessIdentity,
        Capability::AncestorAttribution,
        Capability::AppEnforcement,
        Capability::SessionEnforcement,
        Capability::UserEnforcement,
        Capability::DnsEvidence,
        Capability::HostnameEnforcement,
        Capability::ByteCounters,
        Capability::ExistingFlowRevocation,
        Capability::TelemetryCompleteness,
        Capability::Ipv6Enforcement,
        Capability::UdpEnforcement,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Capability::ProcessIdentity => "process identity",
            Capability::AncestorAttribution => "ancestor attribution",
            Capability::AppEnforcement => "per-app enforcement",
            Capability::SessionEnforcement => "protected-session enforcement",
            Capability::UserEnforcement => "per-user enforcement",
            Capability::DnsEvidence => "DNS evidence",
            Capability::HostnameEnforcement => "hostname enforcement",
            Capability::ByteCounters => "byte counters",
            Capability::ExistingFlowRevocation => "existing-flow revocation",
            Capability::TelemetryCompleteness => "telemetry completeness",
            Capability::Ipv6Enforcement => "IPv6 enforcement",
            Capability::UdpEnforcement => "UDP/QUIC enforcement",
        }
    }
}

/// How well a capability is supported.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// Implemented and covered by tests on the declared matrix.
    Supported,
    /// Implemented with documented conditions (see note).
    Partial,
    /// Implemented, but not yet proven on a real device. Compiles, with a warning.
    Untested,
    /// Not available on this platform/adapter.
    Unsupported,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityStatus {
    pub support: Support,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Macos,
    Linux,
    Windows,
    /// A cooperative DNS resolver (AdGuard Home / Pi-hole). DNS-only coverage.
    DnsResolver,
}

impl Platform {
    pub fn label(&self) -> &'static str {
        match self {
            Platform::Macos => "macOS",
            Platform::Linux => "Linux",
            Platform::Windows => "Windows",
            Platform::DnsResolver => "DNS resolver",
        }
    }
}

/// What an adapter says it can do. Advertised at enrollment and on every restart.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAdvertisement {
    pub platform: Platform,
    pub adapter: String,
    pub adapter_version: String,
    pub capabilities: BTreeMap<Capability, CapabilityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertised_at: Option<DateTime<Utc>>,
}

impl CapabilityAdvertisement {
    pub fn support(&self, c: Capability) -> Support {
        self.capabilities.get(&c).map(|s| s.support).unwrap_or(Support::Unsupported)
    }

    pub fn has(&self, c: Capability) -> bool {
        self.support(c) != Support::Unsupported
    }

    /// The capability set the macOS Network Extension adapter is designed to have.
    /// "Untested" until proven on a real, signed install (see docs/STATUS.md).
    pub fn macos_network_extension() -> Self {
        use Capability::*;
        let mut m = BTreeMap::new();
        let s = |support: Support, note: &str| CapabilityStatus {
            support,
            note: if note.is_empty() { None } else { Some(note.to_string()) },
        };
        m.insert(ProcessIdentity, s(Support::Untested, "source app audit token via NEFilterFlow"));
        m.insert(
            AncestorAttribution,
            s(Support::Unsupported, "needs Endpoint Security entitlement; responsible-process only otherwise"),
        );
        m.insert(AppEnforcement, s(Support::Untested, "NEFilterDataProvider verdicts per flow"));
        m.insert(
            SessionEnforcement,
            s(Support::Unsupported, "no tested macOS session boundary yet; use protected launcher integrations"),
        );
        m.insert(UserEnforcement, s(Support::Untested, ""));
        m.insert(DnsEvidence, s(Support::Partial, "remote hostname when the flow carries it"));
        m.insert(HostnameEnforcement, s(Support::Partial, "only when the flow exposes a hostname; IP otherwise"));
        m.insert(ByteCounters, s(Support::Partial, "NEFilterReport counters under specific reporting conditions"));
        m.insert(ExistingFlowRevocation, s(Support::Unsupported, "not yet tested"));
        m.insert(TelemetryCompleteness, s(Support::Untested, "sequence numbers and gap markers in the spool"));
        m.insert(Ipv6Enforcement, s(Support::Untested, ""));
        m.insert(UdpEnforcement, s(Support::Untested, "QUIC requires device proof"));
        CapabilityAdvertisement {
            platform: Platform::Macos,
            adapter: "moat-macos-ne".into(),
            adapter_version: env!("CARGO_PKG_VERSION").into(),
            capabilities: m,
            advertised_at: None,
        }
    }

    /// The capability set of the Linux nftables + cgroup v2 adapter (linux/moatd).
    pub fn linux_nftables_cgroup() -> Self {
        use Capability::*;
        let mut m = BTreeMap::new();
        let s = |support: Support, note: &str| CapabilityStatus {
            support,
            note: if note.is_empty() { None } else { Some(note.to_string()) },
        };
        m.insert(ProcessIdentity, s(Support::Partial, "pid + start time from /proc; observation only"));
        m.insert(AncestorAttribution, s(Support::Partial, "/proc parent chain at observation time; not a maintained graph"));
        m.insert(AppEnforcement, s(Support::Unsupported, "nftables cannot match executables; use a protected session"));
        m.insert(SessionEnforcement, s(Support::Supported, "cgroup v2 path match (socket cgroupv2); CI netns tests"));
        m.insert(UserEnforcement, s(Support::Supported, "meta skuid"));
        m.insert(DnsEvidence, s(Support::Unsupported, "no resolver integration on the endpoint yet"));
        m.insert(HostnameEnforcement, s(Support::Unsupported, "IP-only; hostname rules need a policy proxy"));
        m.insert(ByteCounters, s(Support::Partial, "per-rule nftables counters, not per flow"));
        m.insert(ExistingFlowRevocation, s(Support::Partial, "new packets of established flows hit the rule; no conntrack flush"));
        m.insert(TelemetryCompleteness, s(Support::Supported, "spool sequence numbers, restart and gap markers"));
        m.insert(Ipv6Enforcement, s(Support::Supported, "inet family table"));
        m.insert(UdpEnforcement, s(Support::Supported, "matches all L4 protocols in the output hook"));
        CapabilityAdvertisement {
            platform: Platform::Linux,
            adapter: "moatd-nftables".into(),
            adapter_version: env!("CARGO_PKG_VERSION").into(),
            capabilities: m,
            advertised_at: None,
        }
    }

    /// A cooperative DNS resolver can only ever offer DNS evidence.
    pub fn dns_resolver(adapter: &str) -> Self {
        let mut m = BTreeMap::new();
        m.insert(
            Capability::DnsEvidence,
            CapabilityStatus {
                support: Support::Supported,
                note: Some("per-client queries when client identity is preserved".into()),
            },
        );
        CapabilityAdvertisement {
            platform: Platform::DnsResolver,
            adapter: adapter.into(),
            adapter_version: "external".into(),
            capabilities: m,
            advertised_at: None,
        }
    }
}
