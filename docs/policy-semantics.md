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
  (`flow_api`, `connect_proxy`, `sni`, `dns_answer`, `inferred`) and a confidence. A flow without hostname evidence
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
`transport = "udp"` → `udp_enforcement`) plus anything listed in `requires`. The compiler checks them against the endpoint's
**advertised** capabilities:

| Rule needs an unsupported capability | Result |
| --- | --- |
| `on_unsupported = "reject"` (default) | The policy does not compile for that platform. Nothing is installed. |
| `on_unsupported = "skip_with_report"`, **allow** rule | Rule omitted from that platform's snapshot and listed in `report.omitted` with the reason. Skipping an allow can only make things stricter. |
| `skip_with_report` on a **deny** rule | Validation error: skipping a deny would weaken policy. |

Session profiles on a platform without session enforcement are listed as `unavailable_session_profiles`, and the
launcher refuses them. Nothing is ever compiled into a weaker rule (conformance: `macos-omits-session-rules`,
`linux-rejects-strict-hostname-rules`, `linux-compiles-with-report`, `dns-resolver-cannot-enforce-sessions`).

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
