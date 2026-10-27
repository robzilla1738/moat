# Protection contract

This is what Moat promises, per platform, and what it does not. Everything Moat shows (in the web UI, the macOS app,
`moatd status`, a notification) must be traceable to a line here. When code and this document disagree, the code is
wrong or this document is out of date. Both are bugs.

> **The claim, narrowly:** selected traffic outside approved policy is prevented *within a stated boundary*, and the
> owner can inspect evidence of the attempt and the enforcement state.

> **Evidence today.** Moat is an experimental build. Nothing below is supported on a real device: no claim in the
> [claim ledger](STATUS.md) is `supported_installed`, and every result comes from GitHub CI runners or unit tests.
> "Implemented" on this page means code plus an automated test in the environment the ledger names. It never means
> proven on Robert's machines (Omarchy, a signed Mac install, phones, the TV).

Moat is not data-loss prevention, not an EDR, not an anti-tamper system, and not a sandbox for arbitrary hostile
software running as the same user. An allowed destination (GitHub, npm, a model API) can still carry data out.

## Three capabilities, never blended

| Capability | Meaning | Where it exists today (ledger claim) |
| --- | --- | --- |
| **Observed activity** | Moat sees a connection and records it. Nothing is blocked. The UI says *observed: permitted, not enforced*. | Linux ordinary apps: **observe-only** inventory (`linux.ordinary-apps.inventory`, `linux.ordinary-apps.connect-attribution`, native CI). Linux ordinary traffic under an observing profile. macOS: the content filter with no signed policy (`observation_no_policy`), never run signed. |
| **Enforced rules** | A signed policy decides; a deny is applied by the OS hook before data passes. | macOS per-app (`macos.filter.app-rules`: component CI, **never run as a signed extension**). Linux device/user-wide via nftables. Linux per-app rules are **rejected** (`linux.ordinary-apps.app-rules`: `unsupported_rejected`). |
| **Protected session** | A boundary established **before the workload executes**, inherited by every descendant, with escape attempts tested. | Linux only: `moat-launch` (cgroup v2 + nftables + broker hiding + uid drop + `no_new_privs`), `linux.session.*` claims, native CI. Not on macOS. |

A launcher that only attaches a session label is an **instrumented session**, never a protected one. The core type
system encodes this (`Boundary::is_containment` in `core/moat-core/src/eval.rs`), and conformance case
`instrumented-session-not-containment` checks it.

## Coverage levels

Shown per device. A device shows the weakest level that is true, never the strongest it was designed for.

| Level | What it claims | What it never claims |
| --- | --- | --- |
| `protected_session` | Traffic from processes inside a tested pre-launch boundary follows the session profile. | That processes outside the session are contained. |
| `enforced` | App/user/device rules from the current signed revision are applied by the OS hook. | Process ancestry (macOS), hostname certainty when only an IP is visible, coverage of brokers. |
| `observed` / `observe_only` | Connections are visible and recorded. Linux ordinary-app inventory labels every record `observe_only` and reports what it missed (`inventory_loss`). | Any blocking. |
| `dns_only` | Cooperative DNS queries from a client are visible and can be refused by the resolver. | A process, a process tree, a completed transfer, a byte count, or blocking of direct-IP / DoH traffic. |
| `degraded` | Something expected is wrong: filter disabled, evaluator error, stale report, telemetry gap, policy not applied, recovery required, rollback pending. | That enforcement is still complete. |
| `isolated` | Emergency isolation is active (new outbound connections are denied except loopback and chosen recovery paths). | That already-open flows were cut, except where measured: on Linux, isolation ends open **proxied** session streams (W05, below). The macOS wording says *new* connections only (`testIsolationWordingMatchesNewFlowScope`). |
| `unknown` | No report, or a report older than 10 minutes. | Anything. |

Phones and the TV are **DNS-only**, always labelled as such (AdGuard Home / Pi-hole adapters in the controller, W16).

## Per-platform contract

### Linux (`moatd`, nftables + cgroup v2)

Every item here is `implemented_unproven` with `native_ci` evidence on a GitHub Ubuntu runner (claims
`linux.session.*`, `linux.activation.trial-rollback`, `linux.packaging.systemd`, `linux.recovery.local-drill`).
**None has run on Robert's Omarchy kernel** ([#6](https://github.com/robzilla1738/moat/issues/6)).

* **Protected sessions.** Placement in `moat.slice/p-<profile>/s-<id>` before `exec`, broker sockets hidden,
  uid/gid dropped to the caller, `no_new_privs`, inherited descriptors closed, session torn down with `cgroup.kill`
  (`linux/moatd/src/launch.rs`, `linux/moatd/tests/privileged.rs`, `linux/tests/netns-enforcement.sh`).
* **Launch authority (W04, #20).** The caller's identity comes from the kernel (`SO_PEERCRED`, cgroup), never from
  the request. A caller already inside a session may launch only its own profile again; a broader nested launch, a
  raw control-socket request and a pre-opened outside connection used from inside a session are refused
  (`linux/moatd/src/caller.rs::contained_callers_cannot_broaden`; netns `W04:` checks, linux-endpoint 40534200207).
  External brokers (docker, ssh-agent) are outside this claim.
* **Ordinary traffic.** Device-wide and per-user rules. **No per-app rules**: nftables cannot tell apps apart, and
  no app-identity hook is proven ([W09](decisions/W09-linux-ordinary-apps.md),
  [W10](decisions/W10-enforcement.md)). The compiler rejects app rules or, for allow rules that opt in, leaves them
  out with a report. Ordinary-app **inventory** exists and is observe-only (W10, #30, #41): socket-table sampling
  and optional bpftrace connect-time attribution, with counted loss. The BPF loader for a future enforcing hook is
  chosen but not built ([W10 increment 3](decisions/W10-increment-3-loader.md); licence decision
  [#53](https://github.com/robzilla1738/moat/issues/53)).
* **Hostnames.** IP-only for ordinary traffic; strict hostname rules there are rejected, never approximated. Inside
  protected sessions, hostname rules are enforced **for TCP only** by the per-session egress proxy
  (`linux/moatd/src/proxy.rs`), from the TLS SNI, a `CONNECT` target or the first plain-HTTP `Host` header, with no
  TLS interception ([proxy contract](proxy-stream-contract.md), W05, #22):
  * **authorization before DNS**: a name no rule can allow is refused without any lookup
    (`hostname_admission()` in `core/moat-core/src/eval.rs`, `core/moat-core/tests/hostname_admission.rs`,
    `proxy.rs::a_name_the_policy_refuses_is_never_looked_up`, netns "W05: no DNS query left the host for a forbidden
    name");
  * **resolved addresses are checked**: every resolved address is evaluated with the hostname evidence, address rules
    (safety denies) still win, and the proxy connects only to an address it resolved, never the client's;
  * **open streams are supervised**: admitted streams are registered and ended on expiry, on a revision that no
    longer allows them, on isolation, on session end and on daemon stop (measured stopping delays in
    linux-endpoint 40537109945; post-decision bytes are bounded by one tick plus socket buffers, not zero);
  * a visible `CONNECT` host vs SNI mismatch is refused before the upstream is dialed (#46,
    `proxy.rs::a_host_mismatch_inside_a_connect_tunnel_is_refused_before_the_upstream_is_dialed`);
  * resource bounds refuse with a `proxy_limit` event, never bypass
    (`proxy.rs::exhaustion_refuses_and_reports_rather_than_bypassing`).
  Limits: fronting through an **encrypted** Host behind an allowed SNI remains possible (it reaches only the allowed
  name's own server; netns "proxy LIMIT (documented)"); ECH exposes only the outer name; UDP stays IP-only.
* **Activation (W06, #23).** Every activation and rollback step is journaled before it changes what is enforced; a
  failure or crash at any step leaves the prior or the committed revision, never a silent permissive state, and a
  persistence failure is reported as `not durable`, never as applied. The replay high-water mark is stored
  independently of the active revision and never lowered. Timed trial revisions revert to the last confirmed
  revision unless confirmed locally; **the first revision cannot be a trial** and the refusal writes nothing.
  Protected sessions running when the daemon restarts are **stopped, not adopted** (`session_not_adopted`;
  decision [#55](https://github.com/robzilla1738/moat/issues/55)). Contract and crash table:
  [linux-activation-journal.md](linux-activation-journal.md); evidence: `linux/moatd/src/endpoint/journal_faults.rs`,
  netns `W06:` checks (linux-endpoint 40539984069). The trial countdown needs the daemon running; a stopped daemon
  reverts at its next start.
* **Installed unit (W11, #24).** The packaged `moatd.service` runs under systemd on an Ubuntu runner and its
  workloads can write their project while containment probes still fail (`linux/tests/installed-unit.sh`). The unit
  keeps `CAP_SYS_PTRACE` (decision [#54](https://github.com/robzilla1738/moat/issues/54)). Not the Arch package on
  Omarchy.
* Gaps listed in [platforms/linux.md](platforms/linux.md#what-a-linux-protected-session-does-not-cover): abstract
  Unix sockets, the system resolver as a broker, unhidden loopback brokers, root/kernel, interactive TTY job control
  without the PTY proxy.

### macOS (`MoatFilter` system extension, NEFilterDataProvider)

Claim `macos.filter.app-rules`: `implemented_unproven`, component evidence on the unsigned `macos-26` runner
(macos 40577981264). **Never run as a signed, approved system extension**
([#2](https://github.com/robzilla1738/moat/issues/2), [#7](https://github.com/robzilla1738/moat/issues/7)).

* Per-flow verdicts for **outbound** socket flows, keyed on the source app's audit token (signing identifier, team
  ID, path). Inbound flows are not filtered. The actual process and the responsible app are kept separate
  (`testActualProcessAndResponsibleAppStaySeparate`).
* A deny is a `.drop()` at the new-flow decision point: recorded as *blocked before data was sent*. Allowed flows
  report bytes only when macOS delivers an `NEFilterReport`; otherwise *amount sent not measured*.
* **Evaluator, cache and trust (W07, #19).** Decisions come from one generation-bound evaluator; cache entries
  belong to one policy generation and never outlive a timed permission; a failed candidate keeps the running
  evaluator; restored state is re-verified and tampered state refused; a failed write is never reported as durable;
  trust changes reach the running verifier (`reloadTrust` XPC operation). Tests:
  `macos/MoatKit/Tests/MoatKitTests/W07Tests.swift`, `StaleTests.swift`.
* **Canary.** A canary revision rolls back unless confirmed. **The first revision cannot be a canary** (there is
  nothing to roll back to); the refusal happens before verification and writes nothing (#62,
  `testFirstRevisionCannotBeACanaryAndTheRefusalWritesNothing`), the same contract as `moatd`.
* **Standalone rule authoring (W12, #29, #45).** The app compiles rules with moat-core over FFI; the owner key in
  the Keychain, behind user presence, signs the exact snapshot; the extension verifies it like any other snapshot.
* **No process ancestry** without the Endpoint Security entitlement (decision
  [#3](https://github.com/robzilla1738/moat/issues/3)). Rules match the app that opened the socket. Process-scoped
  grants stay unavailable (`testProcessScopedGrantsAndAncestryStayUnavailable`).
* **No protected sessions.** Session-scoped rules are omitted from macOS snapshots *with a report*, and session
  profiles are refused at launch (conformance case `macos-omits-session-rules`).
* Every capability is advertised as `untested` until a signed build passes the device proofs in [STATUS.md](STATUS.md).

### DNS resolvers (AdGuard Home / Pi-hole, W16, #44)

* Query visibility for clients that use the resolver, read through version-checked, read-only adapters
  (`controller/src/resolvers.ts`). Claim `dns.adapters.adguard-pihole`: component evidence against recorded responses
  and mocks, **no live resolver** ([#9](https://github.com/robzilla1738/moat/issues/9)). Changing resolver policy is
  not implemented.
* DNS evidence is never an app, process, connection or byte count, and is never sent to Digital Kingdom as an
  endpoint decision ([integrations](integrations.md)). Session rules cannot compile here (conformance case
  `dns-resolver-cannot-enforce-sessions`).

## Grants and authority (W01–W03)

* **Contracts (W01, #13).** Grants, receipts, events, activation states, subjects and capability dispositions are
  versioned schemas with canonical digests and 40 shared fixtures (`contracts/`; consumers
  `core/moat-core/tests/contracts.rs` and `contracts/test/fixtures.test.mjs`).
* **Conservative diff (W02, #16).** The structured diff classifies anything it cannot prove narrowing as broadening
  (profile reorders, shortened denies, unknown fields), checked by a differential counterexample search
  (`core/moat-core/tests/broadening_differential.rs`). The signer reads only `diff.changes[].direction`.
* **Exact grants (W03, #15, #17).** A grant names one device and one task or executable, one destination, one
  transport and port; that scope survives serialization (`core/moat-core/src/grants.rs`). A retried request with the
  same idempotency key returns the original grant and expiry; a different request under that key is refused. Every
  grant is bound to the base policy digest, and the effective digest binds base + overlays + compiler. Process
  grants are refused; Linux ordinary-app grants report `not_enforceable`.
* **Delegated signer authority.** A delegated issuer (a phone key) may approve a grant only within an owner-signed
  `moat.delegation.v1` covering its kind, device and lifetime. Controller-attested grants are off unless the signer
  is started with `MOAT_SIGNER_CONTROLLER_GRANTS=1` (decision [#56](https://github.com/robzilla1738/moat/issues/56)).
  Details: [temporary-grants.md](temporary-grants.md).

## Invariants every component keeps

1. **No silent weakening.** A rule that needs a missing capability is rejected or omitted *with a report*.
2. **No scripts in policy.** Policy is strict declarative data; unknown fields are rejected.
3. **Signed snapshots only.** Endpoints install Ed25519-signed, platform-matched, device-targeted, replay-protected
   snapshots. Nothing promotes trust automatically; trusted keys are owner configuration.
4. **Broadening needs the owner key.** An agent that can edit a policy file cannot authorize its own access.
5. **Agents cannot report verified blocks.** Only an endpoint receipt (and independent observation) can mark an
   enforcement verified (`core/moat-core/src/authority.rs`); the Digital Kingdom feed re-checks producer authority
   before anything leaves (`controller/src/dkfeed.ts`).
6. **No TLS interception.** Hostnames come from the flow API, CONNECT, SNI or DNS, each tagged with source and
   confidence.
7. **Isolation is sticky.** Only a local owner action ends emergency isolation; no heartbeat loss, restart, new policy
   or canary rollback reopens it.
8. **Gaps are shown.** Sequence numbers, restart markers and gap records; enforcement never waits on logging. The
   controller's acknowledgement is a contiguous high-water, and a hole becomes a gap only when the endpoint declares
   it (W13, [fleet-sync.md](fleet-sync.md)).
9. **No byte claims without a measurement.** No "0 bytes transferred" unless measured; never an intended upload size.
10. **The live UI reports evidence, not intent (W08, #14).** *Applied* and *active* come only from endpoint receipts;
    demo data never appears in live mode; a notification reference opens exactly one incident
    ([ui-evidence.md](ui-evidence.md)).
11. **Learning proposes, never trusts (W14, #43, #61).** Captures become candidates that the owner accepts entry by
    entry with the owner key; nothing is accepted by repetition or volume ([learning.md](learning.md)).
12. **No last-writer-wins across the fleet (W13, #42).** A local owner change made offline holds fleet distribution
    to that device until the owner resolves it.
