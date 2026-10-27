//! W06 fault injection: every persistence and backend step of activation and rollback, under disk full, failed
//! rename, torn (corrupt) writes, backend errors and crashes, followed by a restart on the same state directory
//! with the kernel left exactly as the failure left it.
//!
//! Invariants checked after every case (MASTER_ROADMAP §7.1, §7.3, invariants 7, 8, 11):
//! * no "applied" without the commit: the reported revision is the one in the kernel;
//! * failures before the commit keep the prior revision; nothing becomes a silent permissive installation;
//! * rollback intent is retained until restoration is durable;
//! * the replay high-water never goes down;
//! * after restart the state reconciles and a newer revision applies normally.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use chrono::{Duration, Utc};

use super::tests::{applied_revision, events, fixture, make_with, signed, FakeNft, Fixture};
use super::*;
use crate::journal::{Fault, FaultKind, FaultStore};

const STATE: &str = "current.signed.json";

fn faulty(f: &Fixture, crashed: &Arc<AtomicBool>, faults: Vec<Fault>) -> Endpoint<FakeNft> {
    let mut st = FaultStore::new(crashed.clone());
    st.faults = faults;
    let nft = FakeNft { crashed: Some(crashed.clone()), ..Default::default() };
    make_with(f.dir.path(), nft).with_store(Box::new(st))
}

/// Restart: the process is gone, the kernel tables stay as they were, the disk is whatever was written.
fn restart(ep: Endpoint<FakeNft>, dir: &Path) -> Endpoint<FakeNft> {
    let mut ep = ep;
    let mut kernel = std::mem::take(&mut ep.backend);
    drop(ep);
    kernel.crashed = None;
    kernel.fail_apply = false;
    let mut ep2 = make_with(dir, kernel);
    ep2.startup();
    ep2
}

fn kernel_rev(ep: &Endpoint<FakeNft>) -> Option<u64> {
    let l = applied_revision(ep);
    let i = l.find(" revision ")?;
    l[i + 10..].split(' ').next()?.parse().ok()
}

fn phase(ep: &Endpoint<FakeNft>) -> Phase {
    ep.status().activation.unwrap().phase
}

fn hw(ep: &Endpoint<FakeNft>) -> u64 {
    ep.status().activation.unwrap().replay_high_water
}

fn fault(file: &str, kind: FaultKind, skip: usize) -> Fault {
    Fault { file: file.into(), kind, skip }
}

/// Status and kernel agree, and the journal is not stuck mid-activation.
fn consistent(ep: &Endpoint<FakeNft>, want: u64, ctx: &str) {
    assert_eq!(ep.status().revision, Some(want), "{ctx}: reported revision");
    assert_eq!(kernel_rev(ep), Some(want), "{ctx}: kernel revision");
    assert_ne!(phase(ep), Phase::Applying, "{ctx}: journal left applying");
}

/// The steps of a plain apply of revision 2 over confirmed revision 1, by the file each step writes.
/// (file, skip, committed?) — `activation.json` is written twice: the intent (skip 0) and the final phase (skip 1).
const PLAIN_STEPS: [(&str, usize, bool); 5] = [
    ("activation.json", 0, false),
    ("replay-mark", 0, false),
    ("candidate.signed.json", 0, false),
    (STATE, 0, false),
    ("activation.json", 1, true),
];

const TRIAL_STEPS: [(&str, usize, bool); 7] = [
    ("activation.json", 0, false),
    ("replay-mark", 0, false),
    ("candidate.signed.json", 0, false),
    ("lastgood.signed.json", 0, false),
    ("trial.json", 0, false),
    (STATE, 0, false),
    ("activation.json", 1, true),
];

fn run_offer_matrix(trial: bool) {
    let steps: &[(&str, usize, bool)] = if trial { &TRIAL_STEPS } else { &PLAIN_STEPS };
    for &(file, skip, committed) in steps {
        for kind in [FaultKind::DiskFull, FaultKind::RenameFails, FaultKind::Crash] {
            let ctx = format!("trial={trial} fault {kind:?} at {file}#{skip}");
            let (f, _) = fixture();
            let crashed = Arc::new(AtomicBool::new(false));
            let mut ep = faulty(&f, &crashed, vec![]);
            ep.startup();
            ep.offer(signed(&f.key, 1)).unwrap();
            // arm the fault for the next offer only
            let mut st = FaultStore::new(crashed.clone());
            st.faults = vec![fault(file, kind.clone(), skip)];
            ep.store = Box::new(st);
            let r = ep.offer_with(signed(&f.key, 2), trial.then_some(60));
            if kind != FaultKind::Crash {
                if committed {
                    assert_eq!(r, Ok(2), "{ctx}");
                    assert_eq!(ep.status().activation.unwrap().durability, "uncertain", "{ctx}");
                    consistent(&ep, 2, &ctx);
                } else {
                    let e = r.expect_err(&ctx);
                    assert!(e.contains("not durable"), "{ctx}: {e}");
                    consistent(&ep, 1, &ctx);
                    assert!(ep.status().trial.is_none(), "{ctx}: no trial without a durable deadline");
                    assert!(
                        events(&ep).iter().any(|ev| matches!(ev, Event::PolicyRejected { kept_revision: Some(1), .. })),
                        "{ctx}: rejection recorded with the kept revision"
                    );
                }
            } else {
                assert!(r.is_err() || committed, "{ctx}");
            }
            let hw_before = hw(&ep);
            // restart on the same disk and kernel
            let ep2 = restart(ep, f.dir.path());
            let want = if committed { 2 } else { 1 };
            consistent(&ep2, want, &format!("{ctx}, after restart"));
            assert!(hw(&ep2) >= hw_before.max(1), "{ctx}: replay high-water lowered");
            assert_eq!(ep2.status().activation.unwrap().durability, "durable", "{ctx}");
            if trial && committed {
                assert_eq!(phase(&ep2), Phase::Trial, "{ctx}");
                let t = ep2.status().trial.expect("trial survives");
                assert_eq!((t.revision, t.fallback_revision), (2, 1), "{ctx}");
            } else {
                assert_eq!(phase(&ep2), Phase::Confirmed, "{ctx}");
                assert!(ep2.status().trial.is_none(), "{ctx}: no trial for an uncommitted revision");
            }
            // the endpoint is usable: a newer revision applies
            let mut ep2 = ep2;
            assert_eq!(ep2.offer(signed(&f.key, 3)), Ok(3), "{ctx}");
            consistent(&ep2, 3, &ctx);
        }
    }
}

#[test]
fn every_plain_apply_step_survives_disk_full_failed_rename_and_crash() {
    run_offer_matrix(false);
}

#[test]
fn every_trial_apply_step_survives_disk_full_failed_rename_and_crash() {
    run_offer_matrix(true);
}

#[test]
fn backend_error_keeps_the_prior_revision_and_no_trial() {
    let (f, mut ep) = fixture();
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    ep.backend.fail_apply = true;
    let e = ep.offer_with(signed(&f.key, 2), Some(60)).unwrap_err();
    assert!(e.contains("nft apply failed"), "{e}");
    consistent(&ep, 1, "backend error");
    assert!(ep.status().trial.is_none());
    assert!(TrialState::load(f.dir.path()).is_none(), "the trial file written before the kernel step is removed");
    assert_eq!(phase(&ep), Phase::Confirmed);
    ep.backend.fail_apply = false;
    let ep2 = restart(ep, f.dir.path());
    consistent(&ep2, 1, "backend error, restart");
}

#[test]
fn an_aborted_trial_over_a_pending_trial_restores_the_pending_one() {
    let (f, _) = fixture();
    let crashed = Arc::new(AtomicBool::new(false));
    let mut ep = faulty(&f, &crashed, vec![]);
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    ep.offer_with(signed(&f.key, 2), Some(600)).unwrap();
    // crash after the new trial file replaced the pending one, before the kernel
    let mut st = FaultStore::new(crashed.clone());
    st.faults = vec![fault(STATE, FaultKind::Crash, 0)];
    ep.store = Box::new(st);
    assert!(ep.offer_with(signed(&f.key, 3), Some(60)).is_err());
    let ep2 = restart(ep, f.dir.path());
    consistent(&ep2, 2, "pending trial restored");
    let t = ep2.status().trial.expect("the pending trial of revision 2 is still pending");
    assert_eq!((t.revision, t.fallback_revision), (2, 1));
    assert_eq!(phase(&ep2), Phase::Trial);
}

#[test]
fn a_torn_commit_is_reported_as_recovery_required_not_reset() {
    let (f, _) = fixture();
    let crashed = Arc::new(AtomicBool::new(false));
    let mut ep = faulty(&f, &crashed, vec![]);
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    let mut st = FaultStore::new(crashed.clone());
    st.faults = vec![fault(STATE, FaultKind::Corrupt, 0), fault("activation.json", FaultKind::Crash, 1)];
    ep.store = Box::new(st);
    let _ = ep.offer(signed(&f.key, 2));
    let ep2 = restart(ep, f.dir.path());
    // the stored snapshot is unreadable: no policy is claimed, the kernel table is left as it was (not deleted)
    assert_eq!(ep2.status().revision, None);
    assert_eq!(phase(&ep2), Phase::RecoveryRequired);
    assert_eq!(ep2.status().coverage, "recovery-required");
    assert!(!ep2.status().enforcement_active);
    assert!(ep2.backend.tables.contains_key("moat"), "never removes what is enforced");
    assert!(ep2.backend.deleted.is_empty());
    assert!(ep2.launch_refusal("coding-session", 4242).unwrap().contains("no valid policy"));
    // replay protection survives: revision 2 cannot be replayed; a newer signed revision restores a known state
    let mut ep2 = ep2;
    assert!(ep2.offer(signed(&f.key, 2)).is_err());
    assert_eq!(ep2.offer(signed(&f.key, 3)), Ok(3));
    assert_eq!(phase(&ep2), Phase::Confirmed);
    assert_eq!(ep2.status().coverage, "protected-session");
}

#[test]
fn corrupt_journal_is_visible_and_never_a_fresh_bootstrap() {
    let (f, mut ep) = fixture();
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    ep.offer(signed(&f.key, 2)).unwrap();
    std::fs::write(f.dir.path().join(journal::FILE), b"{\"schema\": \"moatd.activation_jour").unwrap();
    let ep2 = restart(ep, f.dir.path());
    assert_eq!(phase(&ep2), Phase::RecoveryRequired);
    assert_eq!(ep2.status().coverage, "recovery-required");
    // the last verified snapshot stays enforced; nothing weaker is installed
    assert_eq!(ep2.status().revision, Some(2));
    assert_eq!(kernel_rev(&ep2), Some(2));
    assert!(f.dir.path().join("activation.json.corrupt").exists(), "the corrupt journal is kept for diagnosis");
    assert!(events(&ep2).iter().any(|e| matches!(e, Event::ActivationRecovery { phase, .. } if phase == "recovery_required")));
    let mut ep2 = ep2;
    assert!(ep2.offer(signed(&f.key, 2)).is_err(), "replay still refused");
    assert_eq!(ep2.offer(signed(&f.key, 3)), Ok(3));
    assert_eq!(phase(&ep2), Phase::Confirmed);
}

#[test]
fn corrupt_replay_mark_falls_back_to_the_journal_copy() {
    let (f, mut ep) = fixture();
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    ep.offer_with(signed(&f.key, 5), Some(60)).unwrap();
    ep.tick_trial(Utc::now() + Duration::seconds(61));
    consistent(&ep, 1, "rolled back");
    std::fs::write(f.dir.path().join(trial::REPLAY_MARK), b"\x00garbage").unwrap();
    let mut ep2 = restart(ep, f.dir.path());
    assert_eq!(hw(&ep2), 5, "the high-water comes from the journal, not the active revision");
    assert!(ep2.offer(signed(&f.key, 4)).is_err(), "a revision below the high-water is a replay");
    assert!(ep2.offer(signed(&f.key, 5)).is_err());
    assert_eq!(ep2.offer(signed(&f.key, 6)), Ok(6));
    assert_eq!(std::fs::read_to_string(f.dir.path().join(trial::REPLAY_MARK)).unwrap().trim(), "6");
}

#[test]
fn rollback_intent_is_retained_until_the_restore_is_durable() {
    let (f, _) = fixture();
    let crashed = Arc::new(AtomicBool::new(false));
    let mut ep = faulty(&f, &crashed, vec![]);
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    ep.offer_with(signed(&f.key, 2), Some(60)).unwrap();
    // the restore reaches the kernel, but making it durable fails (disk full) twice
    let mut st = FaultStore::new(crashed.clone());
    st.faults = vec![fault(STATE, FaultKind::DiskFull, 0), fault(STATE, FaultKind::DiskFull, 0)];
    ep.store = Box::new(st);
    let late = Utc::now() + Duration::seconds(61);
    ep.tick_trial(late);
    assert_eq!(phase(&ep), Phase::RollbackRequired);
    assert_eq!(ep.status().coverage, "rollback-pending");
    assert_eq!(ep.status().revision, Some(1), "the kernel enforces the fallback and status says so");
    assert_eq!(kernel_rev(&ep), Some(1));
    assert!(TrialState::load(f.dir.path()).is_some(), "trial file (rollback intent) kept");
    ep.tick_trial(late);
    let failures = events(&ep).iter().filter(|e| matches!(e, Event::PolicyRollbackFailed { .. })).count();
    assert_eq!(failures, 1, "a retried rollback does not flood the spool");
    // restart while still pending: the journal still says rollback_required, and startup completes it
    let ep2 = restart(ep, f.dir.path());
    consistent(&ep2, 1, "rollback completed after restart");
    assert_eq!(phase(&ep2), Phase::Confirmed);
    assert!(ep2.status().trial.is_none());
    assert_eq!(hw(&ep2), 2, "rollback never lowers the replay high-water");
    let mut ep2 = ep2;
    assert!(ep2.offer(signed(&f.key, 2)).is_err(), "the reverted revision cannot be replayed");
}

#[test]
fn a_failed_rollback_is_retried_and_never_becomes_confirmed() {
    let (f, mut ep) = fixture();
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    ep.offer_with(signed(&f.key, 2), Some(60)).unwrap();
    ep.backend.fail_apply = true;
    let late = Utc::now() + Duration::seconds(61);
    for _ in 0..3 {
        ep.tick_trial(late);
    }
    assert_eq!(phase(&ep), Phase::RollbackRequired);
    consistent(&ep, 2, "failed rollback keeps the trial revision, visibly");
    assert!(ep.status().last_rejection.unwrap().contains("retrying"));
    assert_eq!(events(&ep).iter().filter(|e| matches!(e, Event::PolicyRollbackFailed { .. })).count(), 1);
    // a new trial cannot start on top of a pending rollback
    assert!(ep.offer_with(signed(&f.key, 3), Some(60)).unwrap_err().contains("rollback is still pending"));
    ep.backend.fail_apply = false;
    ep.tick_trial(late);
    consistent(&ep, 1, "retry succeeds");
    assert_eq!(phase(&ep), Phase::Confirmed);
}

#[test]
fn a_crash_during_rollback_resumes_it_on_restart() {
    for file in ["activation.json", STATE, "trial.json"] {
        let (f, _) = fixture();
        let crashed = Arc::new(AtomicBool::new(false));
        let mut ep = faulty(&f, &crashed, vec![]);
        ep.startup();
        ep.offer(signed(&f.key, 1)).unwrap();
        ep.offer_with(signed(&f.key, 2), Some(1)).unwrap();
        let mut st = FaultStore::new(crashed.clone());
        st.faults = vec![fault(file, FaultKind::Crash, 0)];
        ep.store = Box::new(st);
        // a real deadline, so the restarted daemon sees the trial as due too
        std::thread::sleep(std::time::Duration::from_millis(1100));
        ep.tick_trial(Utc::now());
        let ep2 = restart(ep, f.dir.path());
        consistent(&ep2, 1, &format!("crash at {file} during rollback"));
        assert!(ep2.status().trial.is_none(), "crash at {file}");
        assert_eq!(phase(&ep2), Phase::Confirmed, "crash at {file}");
        assert_eq!(hw(&ep2), 2);
    }
}

#[test]
fn first_canary_needs_a_fallback_and_writes_nothing() {
    let (f, mut ep) = fixture();
    ep.startup();
    assert!(ep.offer_with(signed(&f.key, 1), Some(60)).unwrap_err().contains("fall back to"));
    assert_eq!(phase(&ep), Phase::None);
    assert!(!f.dir.path().join(STATE).exists());
    assert!(!f.dir.path().join(trial::FILE).exists());
    assert!(ep.backend.applied.is_empty(), "nothing reached the kernel");
}

#[test]
fn sessions_running_across_a_restart_are_stopped_not_adopted() {
    let (f, mut ep) = fixture();
    ep.startup();
    ep.offer(signed(&f.key, 1)).unwrap();
    let orphan = f.dir.path().join("cg/moat.slice/p-coding-session/s-20261027-old");
    std::fs::create_dir_all(&orphan).unwrap();
    let ep2 = restart(ep, f.dir.path());
    assert!(!orphan.exists(), "the orphaned session cgroup is stopped and removed");
    assert!(events(&ep2).iter().any(|e| matches!(e,
        Event::SessionNotAdopted { session_id, profile, reason }
            if session_id == "20261027-old" && profile == "coding-session" && reason.contains("not adopted"))));
    assert!(ep2.status().sessions.is_empty());
}
