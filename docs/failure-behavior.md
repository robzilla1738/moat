# Failure behavior

What each component does when something goes wrong, what is implemented, and what still needs proof on a real device.
"Implemented" means code plus an automated test; "device proof" means it must still be observed on Robert's hardware
before the UI may claim it (see [STATUS.md](STATUS.md)).

| Failure | Required behavior (roadmap) | Linux `moatd` | macOS `MoatFilter` | Controller / web |
| --- | --- | --- | --- | --- |
| Controller unreachable | Keep the last valid local policy; buffer a bounded backlog. | Implemented: last verified snapshot re-verified at boot and enforced; spool keeps writing under quota. netns test "offline restart". | Implemented in MoatKit: policy state persisted under `/Library/Application Support/Moat/state`; the extension never contacts the controller. Device proof needed. | Implemented: a device silent for 10 minutes is `stale` with effective coverage *degraded* (never its last claim); "applied" only from an endpoint receipt. |
| No valid policy for a protected run | Refuse to launch with an actionable reason. | Implemented: `moat-launch` exits 126 with the reason; never runs unprotected. | Not applicable: macOS has no protected sessions; session profiles are refused (compile report). | Harness launch API returns the refusal. |
| No signed policy at all (ordinary apps) | Explicit permissive observation, labeled. | Implemented: nothing is enforced; status says so. | Implemented: `observation_no_policy` decisions, coverage *observed*. | Coverage *monitoring*. |
| Recognizer or ancestry uncertain | Label it; protected runs stay restrictive; ordinary apps follow the fallback profile. | Implemented: session membership comes from the cgroup, not names. | Implemented: ancestry always reported as unavailable; rules match the socket-owning app. | Chains marked incomplete in the UI. |
| Filter/daemon crash or OS disables the extension | Report loss of coverage when observable. **Do not promise fail-closed.** | nftables rules stay loaded when the daemon dies (the kernel enforces them), but this is a property of nftables, not a promise. Restart writes a `restart` record; unclean shutdown is flagged. Device proof needed on Omarchy. | When the filter is disabled or stopped, the app shows *degraded*. What macOS does with flows while the extension is crashed/upgrading is **unknown until tested**; no fail-closed claim. | Stale → *degraded* (above). A reported `degraded` coverage change raises a high-urgency `coverage_lost` incident and notification. |
| Evaluator error | Not specified; must not be silent. | n/a (rules are compiled into nftables). | Implemented: fallback verdict (deny by default), source `evaluator_error`, coverage *degraded*. | — |
| Event disk full or sequence gap | Enforcement independent of logging; show the gap. | Implemented: quota → drop + `gap` record with exact range; tested. | Implemented: in-memory ring with overflow/restart `GapMarker`s shown in Activity/Coverage. | Gaps shown per device (`telemetryGaps`). |
| Malformed or unsupported policy | Reject atomically; keep the last working revision. | Implemented: verify → render → `nft -c` → one atomic `nft -f`; tested. | Implemented: verify (moat-core via FFI) before write; atomic file write; rejection shown with reason. | Signer refuses to sign invalid or broadening-without-owner-key changes. |
| Replayed snapshot | Reject. | Implemented. | Implemented; the replay high-water mark survives local rollback. | Revision states tracked separately. |
| Broad rule breaks management | Timed canary rollback and local recovery; isolation must not reopen on heartbeat loss. | Implemented: `moatd apply --trial-secs N` reverts to the last confirmed revision unless `moatd recover confirm` runs first; `recover rollback` reverts now; local recovery (`disable/resume/isolate/clear-isolation`). The countdown needs the daemon running; a trial past its deadline while `moatd` was stopped is reverted at the next start. Checked in CI on a real kernel; Omarchy untested. | Implemented: canary apply (10 min default in the UI) rolls back unless confirmed; local "roll back to last known good"; isolation persisted and only cleared by a typed owner confirmation. | Controller rollback is a new signed revision with older content. |
| Emergency isolation + controller loss | Must stay isolated. | Implemented and tested (isolation table survives restart and new policy). | Implemented and unit-tested (survives restart, canary rollback, new policy). Device proof needed. | — |
| Signer key compromise / rotation | Out of the initial claim; support revocation. | Trusted-key directory; revoke by removing the key. | `revoke <key_id>` lines in the trusted-keys file. | Separate signer identity; owner key separate from controller key. |

## What the UI must never do

* Show *applied* without an endpoint receipt; show *verified* without an independent observation.
* Hide a gap, a stale device, or a disabled filter behind an overall "healthy".
* Promise fail-closed behavior on any platform before the matching device proof in [STATUS.md](STATUS.md) passes.
