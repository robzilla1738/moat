//! `moat.receipt.v1`: an endpoint's signed statement about its activation state at one observation time.
//!
//! A receipt says when it was observed, on which boot, at which sequence, with how much clock uncertainty. Each
//! consumer computes freshness itself from those fields (`Receipt::freshness`); a sender-supplied health label is
//! display text and can never make an old receipt current (W01 acceptance).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::activation::{ActivationPhase, Durability, GenerationRef};
use super::{cerr, check_digest, check_id, check_time, finish, parse_time, Contract, ContractError};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ClockSource {
    /// System clock known to be synchronized (NTP/chrony/timed reported sync).
    Synchronized,
    /// System clock, sync state unknown.
    Unknown,
    /// System clock known to be unsynchronized.
    Unsynchronized,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Clock {
    pub source: ClockSource,
    /// Bound on |endpoint clock - true time| in milliseconds, as far as the endpoint knows.
    pub uncertainty_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptActivation {
    pub phase: ActivationPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<GenerationRef>,
    pub replay_high_water: u64,
    pub capability_generation: u64,
    pub durability: Durability,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    pub receipt_id: String,
    pub device_id: String,
    pub boot_id: String,
    /// Per-boot monotonically increasing sequence. (boot_id, sequence) orders receipts; wall time does not.
    pub sequence: u64,
    /// Producing component, e.g. `moatd`. Its authority is `endpoint_enforcer`; a receipt is not independent
    /// evidence of a network effect.
    pub producer: String,
    /// Endpoint wall-clock time the state was observed.
    pub observed_at: String,
    /// Milliseconds since boot at observation (monotonic within the boot).
    pub monotonic_ms: u64,
    pub clock: Clock,
    pub activation: ReceiptActivation,
    /// Sender's own label ("healthy", ...). Display only; never used to compute freshness or status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_label: Option<String>,
}

/// How current a receipt is, as computed by the consumer.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Observed within `max_age` even under worst-case clock error.
    Fresh,
    /// Possibly older than `max_age`.
    Stale,
    /// The observation time cannot be trusted (in the future beyond its stated uncertainty, or unsynchronized).
    Unknown,
}

impl Receipt {
    /// Consumer-side freshness: the receipt is fresh only if `observed_at`, pushed back by its clock uncertainty,
    /// is still within `max_age` of the consumer's `now`. A future timestamp beyond the stated uncertainty, or an
    /// unsynchronized clock, is `unknown`.
    pub fn freshness(&self, now: DateTime<Utc>, max_age: Duration) -> Freshness {
        let Some(at) = parse_time(&self.observed_at) else { return Freshness::Unknown };
        if self.clock.source == ClockSource::Unsynchronized {
            return Freshness::Unknown;
        }
        let unc = Duration::milliseconds(self.clock.uncertainty_ms.min(i64::MAX as u64) as i64);
        if at - unc > now {
            return Freshness::Unknown;
        }
        let worst_age = now - (at - unc);
        if worst_age <= max_age {
            Freshness::Fresh
        } else {
            Freshness::Stale
        }
    }

    /// Ordering within one device: a receipt from another boot, or with a lower sequence, never supersedes.
    pub fn supersedes(&self, older: &Receipt) -> bool {
        self.device_id == older.device_id && (self.boot_id != older.boot_id || self.sequence > older.sequence)
    }
}

impl Contract for Receipt {
    const SCHEMA: &'static str = "moat.receipt.v1";
    fn validate(&self) -> Result<(), Vec<ContractError>> {
        let mut errs = Vec::new();
        check_id(&self.receipt_id, "$.receipt_id", &mut errs);
        check_id(&self.device_id, "$.device_id", &mut errs);
        check_id(&self.boot_id, "$.boot_id", &mut errs);
        check_id(&self.producer, "$.producer", &mut errs);
        check_time(&self.observed_at, "$.observed_at", &mut errs);
        if let Some(a) = &self.activation.active {
            check_digest(&a.effective_digest, "$.activation.active.effective_digest", &mut errs);
            if a.revision > self.activation.replay_high_water {
                errs.push(cerr("$.activation.active.revision", "exceeds replay_high_water"));
            }
        }
        let committed = matches!(self.activation.phase, ActivationPhase::Confirmed | ActivationPhase::Trial | ActivationPhase::Restored);
        if committed && self.activation.active.is_none() {
            errs.push(cerr("$.activation.active", "a committed phase names its active generation"));
        }
        if self.health_label.as_ref().is_some_and(|l| l.len() > 64) {
            errs.push(cerr("$.health_label", "at most 64 bytes"));
        }
        finish(errs)
    }
}
