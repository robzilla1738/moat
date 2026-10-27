//! Revision deployment state: approved → distributed → received → applied → verified, per device.
//!
//! "Applied" is the endpoint's acknowledgement. "Verified" requires an independent effect observation. A phone
//! notification saying "applied" must correspond to an endpoint acknowledgement, never to "we sent it".

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authority::{check, Assertion, Origin};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RevisionState {
    Approved,
    Distributed,
    Received,
    Applied,
    Verified,
    Rejected,
    Superseded,
}

impl RevisionState {
    pub fn label(&self) -> &'static str {
        match self {
            RevisionState::Approved => "approved",
            RevisionState::Distributed => "distributed",
            RevisionState::Received => "received",
            RevisionState::Applied => "applied",
            RevisionState::Verified => "verified",
            RevisionState::Rejected => "rejected",
            RevisionState::Superseded => "superseded",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub to: RevisionState,
    pub at: DateTime<Utc>,
    pub origin: Option<Origin>,
    pub evidence_ref: Option<String>,
    pub detail: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceRevision {
    pub device_id: String,
    pub revision: u64,
    pub state: RevisionState,
    pub history: Vec<Transition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionError(pub String);

impl DeviceRevision {
    pub fn approved(device_id: &str, revision: u64, at: DateTime<Utc>) -> Self {
        DeviceRevision {
            device_id: device_id.into(),
            revision,
            state: RevisionState::Approved,
            history: vec![Transition { to: RevisionState::Approved, at, origin: None, evidence_ref: None, detail: None }],
        }
    }

    /// Advance the state. `origin` is who reported it; receipts must come from the endpoint enforcer and
    /// verification from an independent observer.
    pub fn advance(
        &mut self,
        to: RevisionState,
        at: DateTime<Utc>,
        origin: Option<Origin>,
        evidence_ref: Option<String>,
        detail: Option<String>,
    ) -> Result<(), TransitionError> {
        use RevisionState::*;
        let ok = matches!(
            (self.state, to),
            (Approved, Distributed)
                | (Distributed, Received)
                | (Received, Applied)
                | (Applied, Verified)
                | (Distributed, Rejected)
                | (Received, Rejected)
                | (Approved, Superseded)
                | (Distributed, Superseded)
                | (Received, Superseded)
                | (Applied, Superseded)
                | (Verified, Superseded)
        );
        if !ok {
            return Err(TransitionError(format!("cannot go from {} to {}", self.state.label(), to.label())));
        }
        let need = match to {
            Received => Some(Assertion::PolicyReceived),
            Applied | Rejected => Some(Assertion::PolicyApplied),
            Verified => Some(Assertion::EffectVerified),
            _ => None,
        };
        if let Some(a) = need {
            let o = origin.ok_or_else(|| TransitionError(format!("{} needs a reporting origin", to.label())))?;
            check(o, a).map_err(|v| TransitionError(v.detail))?;
            if to == Verified && evidence_ref.is_none() {
                return Err(TransitionError("verification needs an evidence reference".into()));
            }
        }
        self.state = to;
        self.history.push(Transition { to, at, origin, evidence_ref, detail });
        Ok(())
    }
}

/// Fleet-wide view of one revision.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct RolloutSummary {
    pub revision: u64,
    pub counts: BTreeMap<String, usize>,
    pub unacknowledged: Vec<String>,
}

pub fn summarize(revision: u64, devices: &[DeviceRevision]) -> RolloutSummary {
    let mut s = RolloutSummary { revision, ..Default::default() };
    for d in devices.iter().filter(|d| d.revision == revision) {
        *s.counts.entry(d.state.label().to_string()).or_default() += 1;
        if matches!(d.state, RevisionState::Approved | RevisionState::Distributed | RevisionState::Received) {
            s.unacknowledged.push(d.device_id.clone());
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> DateTime<Utc> {
        "2026-10-26T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn happy_path_requires_right_origins() {
        let mut d = DeviceRevision::approved("mbp-m1", 9, t());
        d.advance(RevisionState::Distributed, t(), None, None, None).unwrap();
        assert!(d.advance(RevisionState::Received, t(), Some(Origin::RuntimeSelfReport), None, None).is_err());
        d.advance(RevisionState::Received, t(), Some(Origin::EndpointEnforcer), None, None).unwrap();
        d.advance(RevisionState::Applied, t(), Some(Origin::EndpointEnforcer), None, None).unwrap();
        assert!(d.advance(RevisionState::Verified, t(), Some(Origin::EndpointEnforcer), Some("canary-1".into()), None).is_err());
        assert!(d.advance(RevisionState::Verified, t(), Some(Origin::IndependentObserver), None, None).is_err());
        d.advance(RevisionState::Verified, t(), Some(Origin::IndependentObserver), Some("canary-1".into()), None).unwrap();
        assert_eq!(d.history.len(), 5);
    }

    #[test]
    fn cannot_skip_states() {
        let mut d = DeviceRevision::approved("mbp-m1", 9, t());
        assert!(d.advance(RevisionState::Applied, t(), Some(Origin::EndpointEnforcer), None, None).is_err());
    }

    #[test]
    fn summary_lists_unacknowledged() {
        let mut a = DeviceRevision::approved("a", 3, t());
        a.advance(RevisionState::Distributed, t(), None, None, None).unwrap();
        let b = DeviceRevision::approved("b", 3, t());
        let s = summarize(3, &[a, b]);
        assert_eq!(s.unacknowledged.len(), 2);
    }
}
