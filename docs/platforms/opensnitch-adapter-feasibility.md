# OpenSnitch adapter: feasibility assessment

**Question (roadmap §6, phase 0 item 4):** can a maintained OpenSnitch adapter supply Moat's required Linux policy
semantics, events and device integration, so Moat does not need its own Linux enforcement path?

**Status:** desk assessment from OpenSnitch's public documentation and protocol definitions
([Nodes](https://github.com/evilsocket/opensnitch/wiki/Nodes), [Rules](https://github.com/evilsocket/opensnitch/wiki/Rules),
[architecture](https://github.com/evilsocket/opensnitch/wiki/Dependencies-and-how-it-works), `proto/ui.proto`).
**Not yet run on Robert's Omarchy machine.** No OpenSnitch code is copied into Moat; OpenSnitch is GPLv3 and an
adapter would talk to it over its gRPC protocol as a separate program (see [licensing](../licensing.md)).

## What OpenSnitch provides

* Netfilter-based enforcement (NFQUEUE) with eBPF-assisted process attribution; per-connection prompts or rules.
* Rules on process path, command line, user id, destination host/IP/network, port, protocol, and lists; rule
  durations (once, until restart, always, timed).
* Ancestor-path matching (`process.parent.path`).
* Multi-node control: daemons connect to a UI server over gRPC (`Subscribe`, `Ping` with statistics, `AskRule`,
  `Notifications` stream for rule changes).
* DNS interception for hostname evidence (hostnames from DNS replies it observed).

## Requirement-by-requirement

| Moat requirement | OpenSnitch | Verdict |
| --- | --- | --- |
| Per-app enforcement on Linux | Yes (process path/cmdline, user) | **Gain**: Moat's nftables adapter cannot do this |
| Hostname evidence | Yes, from observed DNS answers | **Gain** (evidence, not authority: DoH/cached/direct-IP bypass it) |
| Protected sessions established *before* exec | No concept; matching is by path/ancestry after the fact | **Gap**: keep Moat's cgroup supervisor; an adapter cannot replace it |
| Session identity as process instance (pid + start time + boot) | Reports pid/path/cmdline/uid per connection | **Partial**: Moat must add boot id / start generation from /proc |
| Moat precedence (safety > emergency > override > explicit deny > allow > default) | Rule priority by name ordering + "priority" flag; deny/allow/reject per rule | **Partial**: expressible only by careful rule naming/priorities; must be verified by conformance replay against the adapter |
| Strict compile: unsupported needs fail validation | Not applicable (it accepts what it accepts) | Moat compiler stays the gate; the adapter declares its capability contract |
| Signed snapshots, replay protection, atomic install | Rules pushed individually over gRPC; no signed atomic revision | **Gap**: adapter would have to apply a whole revision transactionally (delete + add) and cannot prove atomicity to the kernel |
| Revision receipts (received/applied/verified) | No per-revision acknowledgement | **Gap**: adapter infers "applied" from its own pushes; must be labeled as adapter-reported |
| Sequenced telemetry with gap markers | Statistics + events stream, no sequence numbers | **Gap**: adapter must sequence what it receives and mark daemon reconnects as gaps |
| Byte counters per flow | Not reported per connection | **Gap**: none, or from conntrack accounting separately |
| Existing-flow revocation | Only new connections hit NFQUEUE | **Gap** (same as Moat's nftables path) |
| Unattended operation (no prompts) | Default action + "no prompt" mode configurable | OK with configuration |
| Failure behavior | If the daemon dies, the NFQUEUE rule's `bypass` setting decides: traffic passes or blocks | Must be measured; do not claim fail-closed |
| Offline from controller | Daemon keeps rules locally | OK |
| Licensing | GPLv3 | Separate-process gRPC client is the only plan considered; get a license review before distributing a combined product |

## Recommendation

1. **Keep `moatd` as the Linux authority** for signed revisions, protected sessions (cgroup v2 before exec),
   recovery, spool and receipts. These are the parts OpenSnitch does not provide.
2. **Optionally add an OpenSnitch *sensor/enforcer* adapter** for ordinary-app visibility and per-app rules, as a
   second adapter on the same device with its own capability advertisement (`opensnitch-adapter`: process identity
   partial, per-app enforcement untested, hostname evidence partial, telemetry completeness unsupported until the
   adapter sequences events). The compiler would then route app-scoped rules to it and session rules to `moatd`.
3. **Do not fork OpenSnitch.** A deep fork becomes a second product with its own release cadence.

## Exit criteria to run on Omarchy before committing

* Run Moat's policy conformance cases through the adapter (compile → push → observe decisions) and record every
  divergence.
* Kill the OpenSnitch daemon under load: does traffic pass or block (NFQUEUE bypass)? Record per kernel.
* Measure rule-push atomicity: are there windows where half a revision is active?
* Confirm the adapter can detect daemon restarts and mark spool gaps.
* Confirm OpenSnitch and `moatd`'s nftables table coexist (hook priorities, NFQUEUE vs `reject`).

Until those run, OpenSnitch integration is **design only** and is listed under "needs real-device proof" in
[STATUS](../STATUS.md).
