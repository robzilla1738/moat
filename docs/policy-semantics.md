# Policy semantics

One declarative policy (`schema = "moat.policy.v1"`, TOML or JSON) describes the whole fleet. Each endpoint receives a
**per-platform signed snapshot** compiled from it. This page is the normative description; `core/moat-core` is the
reference implementation and `conformance/` holds implementation-independent cases every adapter must pass.

## No scripts, strict schema

Policy is data. Unknown fields are rejected (`deny_unknown_fields` everywhere). There are no hooks, expressions,
templates or executable callbacks, and service/recognizer packs are data-only too. A policy that cannot be
represented in this schema is a feature request, not an escape hatch.

## Shape

```toml
schema = "moat.policy.v1"
name = "courson-home"
fallback_profile = "ordinary-desktop-learning"   # profile for apps no other profile claims

[device_groups]          # group -> device ids
laptops = ["mbp-m1", "mbp-air"]

[destination_sets.github]   # named destinations (flat; sets cannot nest; never "any")
hosts = ["github.com", "api.github.com", "*.githubusercontent.com"]

[[profiles]]
id = "coding-session"
default = "deny"         # allow | deny | observe
learning = "restrictive" # restrictive profiles must default to deny: time never promotes trust

[[rules]]
id = "coding-allow-github"
action = "allow"                                    # allow | deny
layer = "explicit"                                  # safety | emergency | override | explicit (default)
selector = { session = { profiles = ["coding-session"] } }
destinations = { sets = ["github"] }                # hosts, cidrs, scopes, sets, providers, or any = true
transport = "tcp"                                   # tcp | udp | any
ports = [443]
expires_at = "2026-11-01T00:00:00Z"                 # optional; required for overrides and grants
provenance = { kind = "service_pack", reference = "github@2026.10.1" }
on_unsupported = "skip_with_report"                 # reject (default) | skip_with_report (allow rules only)
```

## Precedence

Evaluated for one flow attempt; the first decisive step wins, and the explanation lists the winning rule **and every
rule it overrode**.

1. **`safety`**: immutable safety/administration constraints (e.g. workloads never reach the controller). Cannot
   come from a grant or pack; never expire.
2. **`emergency`**: deny only.
3. **`override`**: owner-authorized allow; must expire, must be narrow (an app or a session), must carry
   `owner_action` provenance with an audit reference.
4. **`explicit`**: within the layer, **deny beats allow**.
5. **Profile default** of the profile that applies (session profile for a verified protected session, a profile
   whose `applies_to` matches the app, else `fallback_profile`).

So a broad LAN allow cannot silently defeat a workload deny, and a temporary grant cannot override a safety rule
(conformance: `safety-beats-lan-allow`, `safety-beats-tailnet-allow`).

`observe` as a default **permits and records**. Decisions carry `permitted_by_observation = true` and every UI says
*observed: permitted, not enforced*, never *allowed*.

### Profile selection is first match, and order is authority

For ordinary (non-session) traffic the profile is the **first** profile in list order whose `applies_to` matches
the flow; profiles whose `applies_to` is empty or session-scoped never take part. Two profiles can match the same app,
so list order decides which default applies. The diff therefore treats a reorder of selectable profiles with
different defaults as **broadening** (`profile_order_changed`), and any change to a profile's `applies_to` as
broadening, because it moves flows between profiles.

### Broadening classification (W02)

`moat_core::diff` returns structured `changes` (`item`, `kind`, `direction`, `fields`); the human strings are display
only. A change is broadening when it could permit traffic the old policy denied at any time for any subject. It is
narrowing only when the classifier can prove it: an allow that matches a subset of what it matched before (selector,
destinations, transport, ports, lifetime) at the same or lower precedence and with no fewer capability requirements;
or a deny that matches a superset for at least as long at the same or higher precedence. Shortening a deny's expiry,
giving a permanent deny an expiry, narrowing a deny's scope, lowering its layer, raising an allow's layer, removing an
allow's capability requirement, growing a set used by an allow, shrinking a set used by a deny, loosening or
re-scoping a profile, reordering selectable profiles, removing a profile, changing device groups and loosening the
fallback are all broadening. Every field of the policy model is destructured in the classifier, so a new field cannot
be added without classifying it. `core/moat-core/tests/broadening_differential.rs` searches random policy edits for a
denied→permitted counterexample to any non-broadening verdict.

## Selectors

All present fields must match:

* `device_groups`, `users`
* `apps`: any matcher matching is enough; a matcher's fields (`family`, `bundle_id`, `team_id`, `signing_id`,
  `executable` as an absolute path or `*/basename`) must all match. `family` is a recognizer hint, not proof.
* `ancestors`: matches a verified ancestry only. **Requires `ancestor_attribution`**, which macOS lacks without
  Endpoint Security, so such rules do not compile there.
* `session`: `profiles`, `any_protected`, or `session_ids` (instance-bound grants such as *Allow once for this
  session*). Requires `session_enforcement`. An *unverified* session (a label without an OS boundary) is a hint and
  never matches (conformance: `unverified-session-is-a-hint`, `grant-does-not-cover-unverified-session`).

## Destinations

* `hosts` match **hostname evidence** only, never an IP someone once resolved. Evidence carries a source
  (`flow_api`, `connect_proxy`, `sni`, `http_host`, `dns_answer`, `inferred`) and a confidence. A flow without hostname evidence
  does not match a host rule. Leading wildcards only (`*.example.com`).
* `cidrs`, `scopes` (`loopback`, `link_local`, `lan`, `tailnet` (100.64.0.0/10, fd7a:115c:a1e0::/48), `multicast`,
  `public`).
* `providers`: cloud provider / region from downloaded datasets, with an explicit `mode`: `known_ips`,
  `region_endpoints` or `both`. Attribution is approximate; the explanation shows the dataset and date.
* `any = true` must be explicit and cannot be combined with other destinations.

"Localhost, LAN and tailnet allowed" is **not air-gapped**: the profile is called *Private services only*.

## Capabilities and compilation

Each rule implies capabilities from what it references (`apps` → `app_enforcement`; `users` →
`user_enforcement`; `session` → `session_enforcement`; `ancestors` → `ancestor_attribution`; hostnames, directly, via
a set, or via a provider `region_endpoints` match → `hostname_enforcement`; IPv6 CIDRs → `ipv6_enforcement`;
`transport = "udp"` → `udp_enforcement`) plus anything listed in `requires`.

Hostname rules scoped to protected sessions may instead be satisfied by `session_hostname_proxy` (Linux: TCP through
the session egress proxy, from SNI / CONNECT / Host, no TLS interception). Then a hostname **deny** must be
`transport = "tcp"` or the policy does not compile (it would otherwise not cover UDP), and a hostname **allow** on any
transport compiles with a warning that it is enforced for TCP only. Hostname rules for ordinary traffic never use the
proxy. The compiler checks them against the endpoint's
**advertised** capabilities:

| Rule needs an unsupported capability | Result |
| --- | --- |
| `on_unsupported = "reject"` (default) | The policy does not compile for that platform. Nothing is installed. |
| `on_unsupported = "skip_with_report"`, **allow** rule | Rule omitted from that platform's snapshot and listed in `report.omitted` with the reason. Skipping an allow can only make things stricter. |
| `skip_with_report` on a **deny** rule | Validation error: skipping a deny would weaken policy. |

Session profiles on a platform without session enforcement are listed as `unavailable_session_profiles`, and the
launcher refuses them. Nothing is ever compiled into a weaker rule (conformance: `macos-omits-session-rules`,
`linux-ip-only-rejects-strict-hostname-rules`, `linux-ip-only-compiles-with-report`,
`linux-session-proxy-keeps-hostname-allows`, `linux-session-proxy-rejects-udp-hostname-deny`,
`dns-resolver-cannot-enforce-sessions`).

### Profiles are capability-checked too

A profile whose `applies_to` needs a capability the platform lacks (apps, ancestors, users) would hand its flows to
the fallback profile. A **deny** profile in that position fails compilation; a non-deny profile is omitted with a
report (`omission: stricter`) only when the fallback is at least as restrictive. Session-scoped items on a platform
without sessions are omitted as `subject_unavailable`: sessions are refused at launch there, so they can never match.
`report.items` lists the disposition of every profile and rule (contracts `moat.capability_dispositions.v1`).

### Device-targeted snapshots (issue #26)

A fleet policy can hold rules for one device only: an app-scoped block on one Mac, a hostname block on the laptops
group. Compiled fleet-wide for Linux, those rules would be refused (nftables cannot match apps and is IP-only), so one
Mac-only rule used to stop the whole fleet's Linux snapshot.

`CompileOptions.target_devices` (`moatctl compile --device <id>`, repeatable) names the endpoints a snapshot is for:

* A rule or profile whose device scope (`devices` and `device_groups`, combined with AND exactly as the evaluator does)
  includes **none** of the targeted devices can never match there. It is left out, reported in `report.omitted` with
  `not_targeted: true` and disposition `omitted_accepted` / `subject_unavailable`, and is **not** checked against this
  platform's capabilities. The fallback profile is never skipped.
* Every rule that can apply to a targeted device is checked exactly as before: an unsupported restrictive cell on a
  targeted device is still **rejected**. A snapshot targeting several devices is checked for each of them.
* The snapshot records `devices` inside the signed payload. `verify_snapshot_for_device` refuses a targeted snapshot on
  any endpoint not listed, and `verify_snapshot` (no device identity) refuses every targeted snapshot, because a
  snapshot built for another device may lack this device's denies. `moatd` always verifies with its device id; the
  FFI takes `device_id`; `moatctl verify --device`.
* Without `target_devices` the compile is fleet-wide and keeps the conservative behaviour.

The controller compiles one snapshot per platform with that platform's enrolled-device list (`controller/src/signer.ts`
`targets`, passed to `moatctl compile --device`; covered by `controller/test/device-compile.test.ts`):

* A platform with enrolled devices is compiled for exactly those devices and must compile, or the proposal is refused
  before review (`policy does not compile for this fleet: linux (devices omarchy): ...`).
* A platform with no enrolled devices is compiled fleet-wide when that succeeds. When the fleet-wide compile refuses
  (a Mac-only fleet with a Mac app rule), that platform gets **no** snapshot and the publication reports it in
  `skipped_platforms`. Nothing weaker is ever compiled to fill the gap.
* Sync hands a device only the **current** revision's snapshot for its platform, and only if it names the device (or
  is fleet-wide). A device enrolled after the revision was compiled gets `snapshot: null` with `snapshot_pending`, a
  `not_targeted` revision state and `awaiting_retarget: true` on `GET /v1/devices`, never an older or other-device
  snapshot. The owner runs `POST /v1/policy/retarget`, which republishes the unchanged base and carried grants for the
  current device lists; the signer authorizes it as non-broadening and grant deadlines are not renewed.
* The Mac endpoint passes its device id to `moat_verify_snapshot` (`CoreVerifier(trust:deviceID:)`), and standalone
  local rules carry `devices = ["<this mac>"]` when the id is known.

### Backend identifiers

On Linux, profile ids become cgroup directories and nftables chains and rule ids become counter comments. A policy
whose ids collide after that mapping (`coding.session` vs `coding-session`), or whose rule id imitates a counter the
backend reserves (`default:…`, `observe:…`, `proxy:…`, `session:…`), is rejected at compile time.

## Signing, revisions and rollback

* A snapshot is the exact signed JSON bytes (base64) plus an Ed25519 signature; `key_id = sha256(pub)[..16]`.
* Endpoints check signature, trusted/revoked key, schema, **platform**, **replay** (`revision > last_applied`),
  expiry and policy validity before installing atomically. On failure the last working revision stays.
* A rollback is a **new revision** whose content is older (`rollback_of`), re-authorized by the signer.
* Broadening (a diff that adds access) requires the **owner key**; an agent that can edit Git cannot authorize it.
* Revision state is tracked per device: approved → distributed → received → applied → verified. *Applied* comes only
  from an endpoint receipt; *verified* only from an independent observation.

## Temporary grants

*Allow once for this session* produces an `override`-layer allow in an audited, expiring overlay: bound to the
incident, the current policy revision, the protected-session **instance**, a destination, protocol/port, and the
authenticated owner. A stale action (newer revision, ended session, reused PID) is rejected. Permanent access becomes
a reviewable policy change.

## Simulation

`moatctl simulate` replays a proposed policy against recorded observations: affected apps, newly blocked/allowed
flows, unobserved destinations, platforms that would omit rules, devices that have not acknowledged. It is a
compatibility estimate, **not proof** that unobserved future traffic is safe.
