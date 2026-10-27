# Linux activation journal, rollback and restart contract (W06)

Scope: `moatd` on Linux. Source: `linux/moatd/src/journal.rs` (journal, durable store, fault store),
`linux/moatd/src/endpoint.rs` (`offer_with`, `tick_trial`, `attempt_rollback`, `recover_journal`,
`stop_orphan_sessions`). Tests: `linux/moatd/src/endpoint/journal_faults.rs` and the W06 checks in
`linux/tests/netns-enforcement.sh`.

Disk and kernel updates are not one atomic transaction. W06 does not claim crash atomicity because a rename is
atomic; it claims that **every step is journaled before it changes what is enforced, and every crash point has a
deterministic, tested reconciliation**.

## State on disk (`/var/lib/moatd`)

| File | Meaning |
| --- | --- |
| `activation.json` | Journal: `phase` (moat.activation.v1 names: `none`, `applying`, `trial`, `confirmed`, `rollback_required`, `recovery_required`), `active`, `target`/`prior` while applying, `rollback_target`, `trial_deadline`, the pending trial an activation would replace, and a copy of the replay high-water. |
| `replay-mark` | The replay high-water mark: highest revision ever accepted. Independent of `active`; never lowered. |
| `current.signed.json` | The committed revision (signed snapshot). |
| `candidate.signed.json` | A revision staged for activation (removed after commit or abort). |
| `lastgood.signed.json` | The rollback target of a pending trial (the last confirmed revision). |
| `trial.json` | Trial deadline and local confirm/rollback requests. |

Every write is temp file + `fsync` + `rename` + directory `fsync`.

## Activation sequence and what each failure means

| # | Step | Failure (disk full, failed rename, backend error) | Crash at this step, then restart |
| - | --- | --- | --- |
| 1 | journal `applying {target, prior}` | rejected `not durable`; prior stays | prior stays |
| 2 | replay high-water raised | rejected; prior stays; the revision number is burnt | prior reinstalled |
| 3 | candidate staged; for a trial: rollback target and deadline written | rejected; prior (and any pending trial) stays | prior reinstalled; a replaced pending trial is restored |
| 4 | kernel install (`nft -f`, one transaction) | rejected; prior table untouched; trial file removed | prior reinstalled |
| 5 | commit: candidate → `current` | kernel restored to prior and rejected; if that restore fails, `recovery_required` with the verified new revision kept in force | prior reinstalled |
| 6 | journal `trial` / `confirmed` | accepted, status `durability: uncertain` | completed from `current` |

A torn `current` (a write that "succeeded" with garbage, as on a filesystem without the usual guarantees) is found at
startup: status reports **no policy** and `recovery_required`, the kernel table is **left as it was** (never deleted,
never replaced with something weaker), protected launches are refused, and the replay high-water still refuses
replays. A new signed revision clears it.

A corrupt journal is kept as `activation.json.corrupt`, reported as `recovery_required`, and the last verified
snapshot stays enforced. A corrupt `replay-mark` falls back to the journal's copy (startup takes the maximum of
every readable copy and of every revision on disk). Losing both copies at once is outside the claim.

## Rollback of an unconfirmed trial

1. `rollback_required {from, to}` is journaled **before** the kernel changes; the trial file is kept.
2. The rollback target is re-verified (signature, platform, and that it is revision `to`) and installed.
3. `current` is replaced by the rollback target; only then is the trial file removed and the phase `confirmed`.

If step 2 fails (backend error, missing/invalid target), the trial revision stays in force, status shows
`coverage: rollback-pending` and the reason, one `policy_rollback_failed` event is spooled, and the rollback is
retried on every tick. If step 3 fails, the kernel already enforces `to` and status says so, the phase stays
`rollback_required`, and a restart completes the rollback from the journal. A new trial cannot start while a
rollback is pending. The replay high-water stays at the trial revision, so the reverted revision cannot be replayed.

**First canary:** the first revision on a device cannot be a trial (there is no fallback); the refusal writes
nothing and reaches nothing.

## Daemon restart with protected sessions running

**Contract: stop, not adopt.** Sessions that were running when the previous daemon stopped are killed
(`cgroup.kill`) at startup and reported as `session_not_adopted`. Their control connection, egress proxy and
session-bound grants died with the old process; re-attaching them would silently change their boundary. Until the
new daemon stops them they remain in their profile's chain, which is fail-closed (no session-bound grants, no proxy
redirect). Proxied streams end when `moatd` stops ([proxy-stream-contract.md](proxy-stream-contract.md)).

Consequence for users: restarting or upgrading `moatd` ends running protected sessions. Adoption is a possible
future change and would need its own tests.

## Evidence

* Unit fault matrix (`journal_faults.rs`): every step of a plain apply (5) and a trial apply (7) × disk full,
  failed rename and crash, each followed by a restart on the same disk with the kernel as the failure left it;
  backend error; torn commit; corrupt journal; corrupt replay mark; rollback not durable (retained, completed after
  restart); rollback backend failure (retried, never confirmed, no spool flood); crash at each rollback step; first
  canary; orphan sessions.
* CI netns (`linux-endpoint`): a session running across a real daemon restart is stopped; journal status after
  restart; a real `ENOSPC` on a tmpfs state directory refuses the activation as `not durable` while the prior
  revision stays enforced, and the same revision applies once space returns.
* Not covered: power loss on real storage (fsync semantics of the actual disk), installed systemd unit (W11).
