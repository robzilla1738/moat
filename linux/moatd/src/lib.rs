//! moatd: the Moat Linux endpoint.
//!
//! * [`nft`] renders verified snapshots into one atomic nftables transaction.
//! * [`cgroup`] and [`launch`] establish protected sessions before exec.
//! * [`spool`] keeps a sequenced event spool with restart and gap markers.
//! * [`probe`] downgrades the declared capability contract to what this host can really do.
//! * [`recovery`] is local, root-only and sticky.
//! * [`endpoint`] ties them together; [`server`] and [`control`] expose a few typed local operations.

pub mod caller;
pub mod cgroup;
pub mod control;
pub mod endpoint;
pub mod journal;
pub mod launch;
pub mod nft;
pub mod probe;
pub mod proxy;
pub mod pty;
pub mod recovery;
pub mod server;
pub mod spool;
pub mod trial;
