# Fleet sync contract (W13)

Endpoints and the controller exchange policy and evidence over the mutually authenticated `POST /v1/device/sync`.

## Events: at-least-once, idempotent

* Every spool record carries a stable `(device_id, seq)`; `seq` is continuous across boots (`restart` records carry
  `previous_seq`). The controller stores a record once (`UNIQUE (device_id, seq)`); a resent record is ignored and is
  never a new incident occurrence.
* The response's `acked_seq` is the **contiguous high-water**: every seq at or below it was stored or declared lost.
  The endpoint may drop records at or below it and **must keep and resend** everything above it.
  `pending_ranges` lists holes the controller is still waiting for. Out-of-order delivery is not loss.
* A hole becomes a gap only when the endpoint says it no longer has the records: its own `gap` event (`from`/`to`),
  or `spool_low_seq` (the lowest seq it still holds) in the sync body. Gaps raise `telemetry_gap` incidents and appear
  in diagnostics and "What changed?". Exactly-once network delivery is not claimed.

## Desired vs current

`GET /v1/reconciliation` lists each enrolled device with its desired revision (the newest released to it) and a
state derived from receipts only: `current` (applied/confirmed receipt), `pending` (approved or delivered, no applied
receipt yet), `stale` (no receipt or no contact for 10 minutes), `rejected`, `ahead`, `not_released` (staged rollout)
or `held` (see below). A device is never shown current without its receipt.

## Staged rollout

`POST /v1/rollouts { revision, stages: [{ name, devices }] }` limits a revision to the first stage. Devices outside the
opened stages keep the newest earlier revision released to them. `POST /v1/rollouts/:rev/advance` opens the next stage
only when every device in the opened stages is `current`; otherwise it answers 409 naming who is pending or stale.
A rollout cannot un-send a revision already delivered outside its first stage.

## Offline local changes (no last-writer-wins)

An endpoint that changed policy under local owner authority while the controller was unreachable reports
`local_change { revision, digest, broadening, authorized_by }`. The controller then **holds** fleet distribution to that
device instead of overwriting it, and never adopts the local change into the fleet by recency either.
`POST /v1/devices/:id/local-change/resolve { resolution: "apply_fleet" | "keep_local" }` (owner only) decides.

## Approvals and revocation

An approval prepared against an older policy revision is refused (409) and must be prepared again. A revoked device's
requests are refused (401) and it leaves reconciliation.

## Linux sync agent (moatd outbox)

The reference agent (`moat-controller agent-sync`, `controller/src/agent.ts`) is the only process that talks to the
controller for a Linux endpoint; moatd never does. Each round it:

1. reads `spool/sync-state.json` (`moat.spool_sync_state.v1`, written by moatd). A missing, torn or unknown-schema
   file, or impossible numbers (`spool_low_seq > next_seq`, `acked_seq >= next_seq`, a non-sha256 digest) are not
   believed: the body then carries no `spool_low_seq`/`local_change`, so holes stay pending instead of becoming
   invented gaps. A sync-state for another `device_id` is refused outright.
2. uploads every spool record above `max(agent cursor, moatd acked_seq)` with `spool_low_seq` and `local_change`.
3. writes the controller's contiguous `acked_seq` to `spool/acked` atomically, never lower than the value already
   there or moatd's accepted `acked_seq`, and never beyond `next_seq - 1` (moatd would refuse it; a controller
   claiming more than the endpoint wrote is not believed and the response reports `ack_refused`).
4. follows the controller's `acked_seq` with its cursor, so a lower value (a restored controller) resends what moatd
   still holds; anything already gone is declared by `spool_low_seq`.

A controller outage fails the round before anything is acknowledged; moatd keeps (or evicts with a `gap` record)
and the next round resends. Tests: `controller/test/agent-sync.test.ts` (duplicate, reorder, outage, reconnect with
quota eviction, over-claimed ack, foreign spool, local change held for the owner, stale approval refused).

## Not yet proven

Two real endpoints across a real controller outage, reboot and reconnect have not been exercised; the controller and
agent tests simulate them in-process and over loopback HTTP with the real signer and moatctl, writing moatd's file
formats rather than running moatd. The macOS endpoint does not yet send `spool_low_seq` or `local_change`.
