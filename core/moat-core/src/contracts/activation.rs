//! `moat.activation.v1`: one endpoint's activation state, with every distinct generation kept distinct
//! (MASTER_ROADMAP §7.1): desired, received, verified candidate, active, trial, confirmed rollback target and the
//! anti-replay high-water mark.
//!
//! The phase follows the recoverable lifecycle: candidate → rejected | prepared → applying → trial → confirmed |
//! rollback_required → restored | recovery_required. "Applied" is never reported before the backend commit
//! (§3.3 #11), and rolling back never lowers the replay high-water mark (§3.3 #8).

use serde::{Deserialize, Serialize};

use super::{cerr, check_digest, check_id, check_time, finish, Contract, ContractError};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActivationPhase {
    /// Nothing has ever been activated on this endpoint.
    None,
    /// A verified, authorized candidate is staged; nothing changed yet.
    Prepared,
    /// Durable intent recorded; the backend switch is in progress.
    Applying,
    /// The backend activated the candidate under a trial deadline; the rollback target is retained.
    Trial,
    /// The active generation is confirmed (or was applied without a trial).
    Confirmed,
    /// The trial was rejected or ran out; restoring the rollback target is pending.
    RollbackRequired,
    /// The rollback target is active again.
    Restored,
    /// An interruption or failed restore left state uncertain; operator or reconciler action is required.
    RecoveryRequired,
    /// The last candidate was rejected; the previous active generation (if any) is unchanged.
    Rejected,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    /// The state was fsynced (file and directory) before this record was produced.
    Durable,
    /// The state is in memory only; a restart may lose it.
    NotDurable,
    /// A write failed part-way; what is on disk is not known to match.
    Uncertain,
}

/// A policy generation: revision plus effective digest (base policy + overlays + compiler/schema identity).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationRef {
    pub revision: u64,
    pub effective_digest: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivationState {
    pub schema: String,
    pub device_id: String,
    pub boot_id: String,
    pub phase: ActivationPhase,
    /// What the controller last asked for, as known to this endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired: Option<GenerationRef>,
    /// The newest snapshot the endpoint received (signature not yet necessarily checked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<GenerationRef>,
    /// The newest candidate that passed verification and capability compilation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_candidate: Option<GenerationRef>,
    /// What the backend is enforcing now, if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<GenerationRef>,
    /// Required in `trial`: when the trial reverts unless confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trial_deadline: Option<String>,
    /// The confirmed generation to restore. Required in `trial` and `rollback_required`; retained until a restore
    /// succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_target: Option<GenerationRef>,
    /// Highest revision ever accepted. Independent of `active`; never decreases.
    pub replay_high_water: u64,
    pub durability: Durability,
    /// Why the last candidate was rejected or recovery is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ActivationState {
    fn generations(&self) -> impl Iterator<Item = (&'static str, &GenerationRef)> {
        [
            ("verified_candidate", self.verified_candidate.as_ref()),
            ("active", self.active.as_ref()),
            ("rollback_target", self.rollback_target.as_ref()),
        ]
        .into_iter()
        .filter_map(|(n, g)| g.map(|g| (n, g)))
    }

    /// May a consumer present this endpoint as enforcing `active`? Only when it is committed and durable.
    pub fn is_enforcing_committed(&self) -> bool {
        self.active.is_some()
            && matches!(
                self.phase,
                ActivationPhase::Confirmed | ActivationPhase::Trial | ActivationPhase::Restored | ActivationPhase::Rejected
            )
            && self.durability == Durability::Durable
    }
}

impl Contract for ActivationState {
    const SCHEMA: &'static str = "moat.activation.v1";
    fn validate(&self) -> Result<(), Vec<ContractError>> {
        use ActivationPhase::*;
        let mut errs = Vec::new();
        check_id(&self.device_id, "$.device_id", &mut errs);
        check_id(&self.boot_id, "$.boot_id", &mut errs);
        for (name, g) in [("desired", &self.desired), ("received", &self.received)]
            .into_iter()
            .filter_map(|(n, g)| g.as_ref().map(|g| (n, g)))
            .chain(self.generations())
        {
            check_digest(&g.effective_digest, &format!("$.{name}.effective_digest"), &mut errs);
        }
        // Anything the endpoint verified, activated or keeps as a rollback target was accepted, so the high-water
        // mark covers it. (desired/received may be newer and not yet accepted.)
        for (name, g) in self.generations() {
            if g.revision > self.replay_high_water {
                errs.push(cerr(
                    format!("$.{name}.revision"),
                    "exceeds replay_high_water; the high-water mark never trails an accepted revision",
                ));
            }
        }
        match self.phase {
            None => {
                if self.active.is_some() || self.rollback_target.is_some() {
                    errs.push(cerr("$.phase", "phase none cannot have an active generation or rollback target"));
                }
            }
            Trial => {
                if self.active.is_none() {
                    errs.push(cerr("$.active", "a trial has an active generation"));
                }
                match &self.trial_deadline {
                    Some(t) => {
                        check_time(t, "$.trial_deadline", &mut errs);
                    }
                    Option::None => errs.push(cerr("$.trial_deadline", "required in trial")),
                }
                if self.rollback_target.is_none() {
                    errs.push(cerr("$.rollback_target", "a trial needs a rollback target (the first policy cannot be a trial)"));
                }
            }
            RollbackRequired => {
                if self.rollback_target.is_none() {
                    errs.push(cerr("$.rollback_target", "rollback intent is retained until restoration succeeds"));
                }
            }
            Applying | Prepared => {
                if self.verified_candidate.is_none() {
                    errs.push(cerr("$.verified_candidate", "preparing or applying needs the verified candidate"));
                }
            }
            Confirmed | Restored => {
                if self.active.is_none() {
                    errs.push(cerr("$.active", "confirmed or restored needs an active generation"));
                }
            }
            RecoveryRequired | Rejected => {}
        }
        if self.phase != Trial && self.trial_deadline.is_some() {
            errs.push(cerr("$.trial_deadline", "only a trial has a deadline"));
        }
        if let (Some(a), Some(r)) = (&self.active, &self.rollback_target) {
            if self.phase == Trial && a.revision <= r.revision {
                errs.push(cerr("$.rollback_target", "a trial's rollback target is older than the trial revision"));
            }
        }
        finish(errs)
    }
}
