# Protection contract

This is what Moat promises, per platform, and what it does not. Everything Moat shows (in the web UI, the macOS app,
`moatd status`, a notification) must be traceable to a line here. When code and this document disagree, the code is
wrong or this document is out of date. Both are bugs.

> **The claim, narrowly:** selected traffic outside approved policy is prevented *within a stated boundary*, and the
> owner can inspect evidence of the attempt and the enforcement state.

Moat is not data-loss prevention, not an EDR, not an anti-tamper system, and not a sandbox for arbitrary hostile
software running as the same user. An allowed destination (GitHub, npm, a model API) can still carry data out.

## Three capabilities, never blended

| Capability | Meaning | Where it exists today |
| --- | --- | --- |
| **Observed activity** | Moat sees a connection and records it. Nothing is blocked. The UI says *observed: permitted, not enforced*. | macOS (content filter, design), Linux (ordinary traffic under an observing profile) |
| **Enforced rules** | A signed policy decides; a deny is applied by the OS hook before data passes. | macOS (per-app, *untested on a real signed install*), Linux (device/user-wide via nftables) |
| **Protected session** | A boundary established **before the workload executes**, inherited by every descendant, with escape attempts tested. | Linux only: `moat-launch` (cgroup v2 + nftables + broker hiding + uid drop + `no_new_privs`) |

A launcher that only attaches a session label is an **instrumented session**, never a protected one. The core type
system encodes this (`Boundary::is_containment`), and conformance case `instrumented-session-not-containment`
checks it.

## Coverage levels

Shown per device. A device shows the weakest level that is true, never the strongest it was designed for.

| Level | What it claims | What it never claims |
| --- | --- | --- |
| `protected_session` | Traffic from processes inside a tested pre-launch boundary follows the session profile. | That processes outside the session are contained. |
| `enforced` | App/user/device rules from the current signed revision are applied by the OS hook. | Process ancestry (macOS), hostname certainty when only an IP is visible, coverage of brokers. |
| `observed` | Connections are visible and recorded. | Any blocking. |
| `dns_only` | Cooperative DNS queries from a client are visible and can be refused by the resolver. | A process, a process tree, a completed transfer, a byte count, or blocking of direct-IP / DoH traffic. |
| `degraded` | Something expected is wrong: filter disabled, evaluator error, stale report, telemetry gap, policy not applied. | That enforcement is still complete. |
| `isolated` | Emergency isolation is active (everything but loopback and chosen recovery paths is denied). | That already-open flows were cut (unless the platform proves existing-flow revocation). |
| `unknown` | No report. | Anything. |

Phones and the TV are **DNS-only**, always labeled as such (AdGuard Home / Pi-hole adapters in the controller).

## Per-platform contract

### Linux (`moatd`, nftables + cgroup v2)

* Protected sessions: placement in `moat.slice/p-<profile>/s-<id>` before `exec`, broker sockets hidden, uid/gid
  dropped to the caller, `no_new_privs`, inherited descriptors closed, session torn down with `cgroup.kill`.
  Proven in CI on GitHub's Ubuntu kernel (`linux/tests/netns-enforcement.sh`, `tests/privileged.rs`).
  **Not yet proven on Robert's Omarchy kernel.**
* Ordinary traffic: device-wide and per-user rules. No per-app rules (nftables cannot tell apps apart); the compiler
  rejects them or, for allow rules that opt in, leaves them out with a report.
* Hostnames: IP-only for ordinary traffic; strict hostname rules there are rejected, never approximated. Inside
  protected sessions, hostname rules are enforced **for TCP only** by the session egress proxy, from the TLS SNI, a
  `CONNECT` target or the first plain-HTTP `Host` header, with no TLS interception (labelled *untested* until proven
  on Omarchy). The proxy connects to the name it resolves, never to the client-chosen address. UDP stays IP-only, and
  domain fronting through an allowed host remains possible.
* Timed trial revisions revert to the last confirmed revision unless confirmed locally (daemon must be running for
  the countdown).
* Gaps listed in [platforms/linux.md](platforms/linux.md#what-a-linux-protected-session-does-not-cover): abstract
  Unix sockets, the system resolver as a broker, unhidden loopback brokers, root/kernel, interactive TTY job control.

### macOS (`MoatFilter` system extension, NEFilterDataProvider)

* Per-flow verdicts for **outbound** socket flows, keyed on the source app's audit token (signing identifier, team
  ID, path). Inbound flows are not filtered.
* A deny is a `.drop()` at the new-flow decision point: recorded as *blocked before data was sent*. Allowed flows
  report bytes only when macOS delivers an `NEFilterReport`; otherwise *amount sent not measured*.
* **No process ancestry** without the Endpoint Security entitlement. Rules match the app that opened the socket.
* **No protected sessions.** Session-scoped rules are omitted from macOS snapshots *with a report*, and session
  profiles are refused at launch (conformance case `macos-omits-session-rules`).
* Every capability is advertised as `untested` until a signed build passes the device proofs in [STATUS.md](STATUS.md).

### DNS resolvers (AdGuard Home / Pi-hole)

* Query visibility and refusal for clients that use the resolver. Session rules cannot compile here
  (conformance case `dns-resolver-cannot-enforce-sessions`).

## Invariants every component keeps

1. **No silent weakening.** A rule that needs a missing capability is rejected or omitted *with a report*.
2. **No scripts in policy.** Policy is strict declarative data; unknown fields are rejected.
3. **Signed snapshots only.** Endpoints install Ed25519-signed, platform-matched, replay-protected snapshots.
   Nothing promotes trust automatically; trusted keys are owner configuration.
4. **Broadening needs the owner key.** An agent that can edit a policy file cannot authorize its own access.
5. **Agents cannot report verified blocks.** Only an endpoint receipt (and independent observation) can mark an
   enforcement verified (`authority.rs`).
6. **No TLS interception.** Hostnames come from the flow API, CONNECT, SNI or DNS, each tagged with source and
   confidence.
7. **Isolation is sticky.** Only a local owner action ends emergency isolation; no heartbeat loss, restart, new policy
   or canary rollback reopens it.
8. **Gaps are shown.** Sequence numbers, restart markers and gap records; enforcement never waits on logging.
9. **No byte claims without a measurement.** No "0 bytes transferred" unless measured; never an intended upload size.
