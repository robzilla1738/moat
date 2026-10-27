//! Moat core: the shared, implementation-independent heart of the Moat egress firewall.
//!
//! * [`policy`]: strict declarative policy schema (no scripts, unknown fields rejected)
//! * [`eval`]: precedence and explanation (winning rule + overridden rules)
//! * [`capability`]: capability contracts; unsupported needs fail validation
//! * [`compile`]: per-platform snapshot compiler
//! * [`signing`]: Ed25519-signed snapshots, replay protection, rollback as a new revision
//! * [`revision`]: approved → distributed → received → applied → verified
//! * [`simulate`]: replay a change against recorded observations
//! * [`diff`]: policy diff and broadening detection
//! * [`identity`]: process-instance identity and the process graph
//! * [`recognizer`], [`service_pack`]: data-only packs
//! * [`enrichment`]: provider / ASN / region facts with sources and uncertainty
//! * [`explain`]: deterministic alert explanation templates
//! * [`coverage`]: coverage levels
//! * [`authority`]: which producer may assert what

pub mod authority;
pub mod backend_ids;
pub mod capability;
pub mod compile;
pub mod contracts;
pub mod coverage;
pub mod diff;
pub mod enrichment;
pub mod eval;
pub mod explain;
pub mod grants;
pub mod identity;
pub mod net;
pub mod policy;
pub mod recognizer;
pub mod revision;
pub mod service_pack;
pub mod signing;
pub mod simulate;

pub use capability::{Capability, CapabilityAdvertisement, Platform, Support};
pub use eval::{evaluate, Decision, EvalContext, FlowAttempt, Verdict};
pub use policy::Policy;
