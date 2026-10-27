# Temporary grants (W03): controller and signer

A temporary grant is a `moat.grant.v1` object (`contracts/schemas/moat.grant.v1.schema.json`). Nothing else in the
controller renders grant rules: the Rust core turns each grant into its exact rule.

## Flow

1. **Plan.** `POST /v1/grants/plan` or `POST /v1/actions/allow-once/plan` returns `{ plan_id, plan, context, digest }`.
   `plan` is the complete `moat.grant.v1`: one `device_id`; a task (`task_id` + `boot_id`) or one app executable;
   one address or hostname; one transport and port; `issued_at`/`not_before`/`admission_until` in canonical
   whole-second UTC; `stream_policy = admission_only`; `base_policy_digest` = `sha256:` + canonical digest of the
   current base policy; `issuer` (the owner session, or a delegated key named by `issuer_key_id` at plan time);
   `approval_digest` = digest of `context` (`moat.grant_context.v1`: kind, policy revision, requester, incident).
   `digest` is the canonical contract digest of `plan`, the same value `moatctl contract` prints.
2. **Approve.** A delegated approver (a phone browser) recomputes `digest` from the plan it displays, refuses a
   mismatch, and signs `moat-grant-approval-v1\n<digest>\n` with its own key.
3. **Commit.** `POST /v1/grants` / `POST /v1/actions/allow-once` with `plan_id` (+ `issuer_key_id`,
   `issuer_signature`). The controller re-checks the incident, session and policy revision, then publishes the base
   policy plus every live grant to the signer.
4. **Sign.** The signer normalizes the base, compares it with the last base it signed using `moatctl diff` and reads
   only `diff.changes[].direction`: any `broadening` change needs an owner-key signature over the exact source. It
   compares grants by id and authority digest with the last signed set: a new grant must be structurally exact
   (`grantProblem`), current, bound to this base, and authorized per grant (below). It then runs
   `moatctl compile <base> --grants grants.json` per platform and returns the signed snapshots and
   `report.effective_digest` (base + overlays + compiler).

## Who may authorize a new grant

| Path | Requirement | Default |
|---|---|---|
| Delegated issuer (`delegated_issuer`) | An owner-signed `moat.delegation.v1` covering the grant's kind (`allow_once`/`temporary`), device and lifetime; the grant names that issuer; the issuer signed this grant's digest; `approval_digest` matches the context. | on |
| Controller attestation (`temporary_grant_overlay`) | The grant's issuer is the owner and the controller attests an authenticated owner session asked. | **off**: only when `moat-signer serve` runs with `MOAT_SIGNER_CONTROLLER_GRANTS=1` |

`MOAT_SIGNER_CONTROLLER_GRANTS` stays off by default because with it on, anyone who controls the controller process
(or an owner bearer token) can mint bounded grants without a second device. Turn it on only for a single-user,
single-host setup where the controller and the owner share one trust domain, and know that the signer then trusts the
controller's word for owner presence.

## Invariants (tested in `controller/test/grants.test.ts`)

* Two devices with the same executable never share a single-device grant (the rule carries `selector.devices`).
* Process-scoped grants are refused by both controller and signer: no endpoint enforces a process-generation selector.
* Same idempotency key + same request returns the original plan/grant and `admission_until`; same key + a different
  request is refused (409). A lost signer reply is recovered from the signer's journal, never re-signed differently.
* A grant id is never reused with different content; a removed (revoked) grant cannot be re-added by replaying its
  old approval.
* When the base policy changes, live grants approved against the old base are **superseded** (revoked with
  `ended_reason`), never carried into a policy nobody approved them against.
* An ordinary-app grant for a Linux device is omitted by the compiler (no ordinary-app enforcement there yet); the
  grant status reports `not_enforceable` instead of `active`.
* `active` still requires an endpoint receipt for a revision that carries the grant.

## Limits

Unit and integration evidence (real `moatctl`, real signer process in the e2e) only. No installed endpoint has applied
a grant in CI. Stream behavior is `admission_only`: open connections are not cut at the deadline.
