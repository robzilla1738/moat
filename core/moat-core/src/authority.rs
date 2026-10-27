//! Producer authority: which source may assert what.
//!
//! Adapted from Digital Kingdom's source capabilities (`packages/detections/src/capabilities.ts` @ e0452c8,
//! Apache-2.0): a producer may only assert categories its kind permits. Firewall sensor, launcher, DNS resolver
//! and agent self-report get separate credentials and separate permissions. An agent can never assert a verified
//! block, a policy application, or authorize policy.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// What an agent says about itself ("I am about to fetch X"). Enrichment only.
    RuntimeSelfReport,
    /// The protected launcher (Harness/Dispatch contract).
    Launcher,
    /// The endpoint enforcer (Network Extension / moatd).
    EndpointEnforcer,
    /// An independent effect observer (canary destination, gateway, second sensor).
    IndependentObserver,
    /// A cooperative DNS resolver (AdGuard Home / Pi-hole).
    DnsResolver,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Assertion {
    /// A stated intention.
    Intent,
    SessionLifecycle,
    ConnectionObserved,
    ConnectionBlocked,
    ConnectionAllowed,
    FlowCounters,
    PolicyReceived,
    PolicyApplied,
    /// An independent observation that enforcement had the intended effect.
    EffectVerified,
    DnsQuery,
    CoverageChange,
    /// Authorize a policy change. No producer holds this; only the owner via the signer.
    AuthorizePolicy,
}

/// Default permissions per origin.
pub fn permitted(origin: Origin) -> &'static [Assertion] {
    use Assertion::*;
    match origin {
        Origin::RuntimeSelfReport => &[Intent],
        Origin::Launcher => &[SessionLifecycle, CoverageChange],
        Origin::EndpointEnforcer => &[ConnectionObserved, ConnectionBlocked, ConnectionAllowed, FlowCounters, PolicyReceived, PolicyApplied, CoverageChange],
        Origin::IndependentObserver => &[EffectVerified, ConnectionObserved],
        Origin::DnsResolver => &[DnsQuery, CoverageChange],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityViolation {
    pub origin: Origin,
    pub assertion: Assertion,
    pub detail: String,
}

/// Check whether `origin` may assert `assertion`. `AuthorizePolicy` is never permitted to any producer.
pub fn check(origin: Origin, assertion: Assertion) -> Result<(), AuthorityViolation> {
    if permitted(origin).contains(&assertion) {
        Ok(())
    } else {
        Err(AuthorityViolation {
            origin,
            assertion,
            detail: format!("{origin:?} may not assert {assertion:?}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_cannot_assert_blocks_or_authorize() {
        for a in [Assertion::ConnectionBlocked, Assertion::EffectVerified, Assertion::PolicyApplied, Assertion::AuthorizePolicy] {
            assert!(check(Origin::RuntimeSelfReport, a).is_err());
        }
        assert!(check(Origin::RuntimeSelfReport, Assertion::Intent).is_ok());
    }

    #[test]
    fn nobody_authorizes_policy() {
        for o in [Origin::RuntimeSelfReport, Origin::Launcher, Origin::EndpointEnforcer, Origin::IndependentObserver, Origin::DnsResolver] {
            assert!(check(o, Assertion::AuthorizePolicy).is_err());
        }
    }

    #[test]
    fn dns_cannot_claim_connections() {
        assert!(check(Origin::DnsResolver, Assertion::ConnectionBlocked).is_err());
        assert!(check(Origin::DnsResolver, Assertion::FlowCounters).is_err());
        assert!(check(Origin::EndpointEnforcer, Assertion::EffectVerified).is_err());
    }
}
