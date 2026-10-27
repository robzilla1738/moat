# Moat contracts (W01)

The shared meaning of subject, permission, capability, activation, receipt and event for every component: the Rust
core and Linux endpoint, the Swift macOS app, the TypeScript controller and web UI. Coordinate through these files,
not through each other's code. Schema and semantic decisions have one owner (Lane A); a change here lands, with
fixtures, before any producer or consumer depends on it (MASTER_ROADMAP §19.2).

| Schema id | File | What it is |
| --- | --- | --- |
| `moat.subject.v1` | `schemas/moat.subject.v1.schema.json` | Device, boot, process instance (pid + start generation), authenticated task, executable identity, user. Absent = unknown, never "any". |
| `moat.grant.v1` | `schemas/moat.grant.v1.schema.json` | A temporary permission as a precise object: exact scope, one destination, transport, port, absolute admission window, stream policy, base policy digest, issuer, approval digest, idempotency key. |
| `moat.capability_dispositions.v1` | `schemas/moat.capability_dispositions.v1.schema.json` | Capability cells per endpoint and per-item (profile/rule) dispositions for a compiled policy. |
| `moat.activation.v1` | `schemas/moat.activation.v1.schema.json` | Desired / received / verified candidate / active / trial / rollback target / replay high-water, phase and durability. |
| `moat.receipt.v1` | `schemas/moat.receipt.v1.schema.json` | An endpoint's statement of activation state at one observation time, with boot, sequence and clock uncertainty. |
| `moat.event.v1` | `schemas/moat.event.v1.schema.json` | Event envelope and evidence vocabulary (§5.3). |

Rust reference implementation: `core/moat-core/src/contracts/`. CLI: `moatctl contract <file>` validates any
contract object and prints its canonical digest and form (`--json` for tools).

## Canonical serialization and digests

1. UTF-8 JSON with no insignificant whitespace.
2. Object keys sorted by Unicode code point. Keys are restricted to `[a-z0-9_]+`, so byte order and code-point order
   agree.
3. Optional fields that are absent are **omitted**. `null` is invalid everywhere.
4. Numbers are non-negative integers in `0..=2^53-1`, written without sign, fraction, exponent or leading zeros. A
   parser that cannot tell `443.0` from `443` (JavaScript) must check the number tokens in the raw text.
5. Strings are escaped as `JSON.stringify` / `serde_json` do: `\"`, `\\`, the short forms `\b \f \n \r \t`, other
   control characters as lowercase `\u00xx`; everything else raw UTF-8.
6. Timestamps are strings `YYYY-MM-DDTHH:MM:SSZ`: UTC, whole seconds, no other spelling. Two implementations
   therefore never hash different text for the same instant.
7. IP addresses are written in their canonical text form (RFC 5952 for IPv6; lowercase, compressed). Hostnames are
   lowercase ASCII without wildcards or a trailing dot.
8. Arrays keep their order. Arrays that are sets (e.g. `missing`) must already be sorted ascending without duplicates;
   validation rejects others, so canonical form equals the validated input.
9. Digest = `sha256:` + lowercase hex SHA-256 of the canonical bytes. `Grant::authority_digest` excludes the display
   field `reason`.

## Versions and unknown fields

* The `schema` field names the exact schema id. A consumer **rejects** an id it does not implement (`moat.grant.v2`
  to a v1 consumer): it must not act on an object whose meaning it cannot know.
* Every object rejects unknown fields (`additionalProperties: false`). Producer-specific detail that never affects
  authority, status or freshness goes in an event's `ext` object.
* Unknown enum values are rejected (a producer cannot invent a stronger disposition or phase).
* A breaking change is a new schema id; mixed fleets keep both until every endpoint reports the new one.

## Semantic rules (beyond the JSON schema)

Consumers that act on an object must implement these (fixtures labeled `layer: semantic` exercise them):

* **Grant scope** — `app_on_device` needs `executable` and forbids `boot_id`, `process`, `task_id`;
  `process_instance` needs `boot_id` + `process`, forbids `task_id`; `task` needs `boot_id` + `task_id`, forbids
  `process` and `executable`. `device_id` is always required. Missing mandatory scope rejects the grant.
* **Grant window** — `issued_at <= not_before < admission_until`, window at most 86 400 s. Expiry is absolute: a retry
  with the same `idempotency_key` returns the original grant and original `admission_until`.
* **Stream policy** — `admission_only` stops new admissions at the deadline; `terminate_at_deadline` also ends admitted
  streams and only compiles where the backend has a proven stream-termination cell.
* **Dispositions** — `omitted_accepted` carries `omission`: `stricter` (leaving it out can only make the endpoint stricter; never valid for a `restrictive` item) or `subject_unavailable` (its subjects cannot exist there, e.g. session rules where sessions are refused at launch); `supported_installed` needs `evidence_ref`;
  capability cells are never `omitted_accepted`; item dispositions need the compiled `policy_digest`.
* **Activation** — `replay_high_water` never trails the verified candidate, active generation or rollback target and
  never decreases; `trial` needs `trial_deadline` and a `rollback_target` older than the trial (the first policy cannot
  be a trial); `rollback_required` keeps `rollback_target` until a restore succeeds; there is no "applied" phase
  before the backend commit. Present a generation as enforced only when `active` is set, the phase is committed and
  `durability` is `durable`.
* **Receipt freshness** — computed by the consumer: `unknown` if the clock is unsynchronized or
  `observed_at - uncertainty > now`; otherwise `fresh` iff `now - (observed_at - uncertainty) <= max_age`, else
  `stale`. `health_label` is display text and never changes the result. Order receipts by `(boot_id, sequence)`.
* **Events** — the producer's `authority` must permit what the event asserts (`moat-core::authority`): only an
  `independent_observer` asserts `independently_checked`; agents (`runtime_self_report`) can never assert
  `received`/`activated` or a block. `requested`, `authorized`, `compiled` and `delivered` are controller/signer audit
  facts. Kind-specific fields are required (`lifecycle` → `stage`, `flow_decision` → `decision` + `destination`,
  `gap` → `gap`, `coverage_change` → `coverage`). Measurements state their scope (`flow`, `rule_counter`,
  `conversation_window`, `task`) and source; a rule counter is never presented as per-flow bytes.

## Fixtures

`fixtures/manifest.json` lists every fixture with `expect` (`accept`/`reject`), the canonical digest of each valid
one, the `layer` of each reject, and freshness expectations for receipts. Tests that consume it:

* Rust: `core/moat-core/tests/contracts.rs` (parse, semantic checks, round trip without scope loss, digests, layers).
* JavaScript (no dependencies): `contracts/test/fixtures.test.mjs` (canonicalization, digests, schema-layer rejects,
  freshness) — run with `node --test contracts/test/fixtures.test.mjs`.
* TypeScript (web): `web/src/issuer.test.ts` recomputes the canonical digest of every accepted `moat.grant.v1` fixture,
  the value a phone approver signs.
* Swift: no consumer. The Mac never decodes `moat.*` contract objects natively; snapshots and grants go through
  moat-core over FFI. If Swift ever decodes grants or receipts itself, add a fixture consumer first.
* Controller: compiles grants with the Rust `moatctl compile --grants`; `controller/test/grants.test.ts` checks that
  `moatctl contract` accepts a controller-planned grant and agrees on its digest.

Regenerate with `cd contracts && python3 tools/gen_schemas.py && python3 tools/gen_fixtures.py` only when the contract changes; then
`MOAT_UPDATE_FIXTURES=1 cargo test -p moat-core --test contracts` records new digests. Never edit a digest by hand.
