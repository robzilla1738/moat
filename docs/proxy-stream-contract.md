# Admission vs stream lifetime: the Linux session egress proxy contract (W05)

Scope: TCP from **protected sessions whose profile has hostname rules**, which `moatd` sends through the per-session
egress proxy (`linux/moatd/src/proxy.rs`, described in [platforms/linux.md](platforms/linux.md#session-egress-proxy-hostname-rules-in-protected-sessions)).
Everything else (direct nftables traffic, UDP, macOS) is listed under *Outside this contract* below.

MASTER_ROADMAP §7.2 separates three lifetimes: snapshot admission validity, policy retention, and temporary
permission expiry. This page says what each one does to a connection **when it is opened** (admission) and **while it
is open** (stream).

## 1. Admission: what happens when a connection is opened

1. **Authorization before resolution.** When the client supplies a hostname (TLS SNI, `CONNECT` target, or the first
   plain-HTTP `Host`), the proxy first asks moat-core `hostname_admission()` what the policy can decide about that
   name *without an address*:
   * `deny_without_lookup` — no rule can allow it at any address (a name deny wins, or nothing can allow it and the
     profile default is deny). **No DNS query is made.** The refusal is spooled with `dns_lookup:
     "refused_before_lookup"`.
   * `resolve_allowed_name` — a hostname rule allows the name; it is resolved (`dns_lookup: "allowed_name"`).
   * `resolve_for_address_rules` — only address rules (CIDR, scope, `any`, provider IP sets) could allow it, so the
     name has to be resolved to know. This **is** a DNS exposure the policy implies, and it is recorded as
     `dns_lookup: "address_rules_exposure"`. A profile that must not leak names should not combine hostname
     traffic with broad address allows.
   The pre-lookup answer is exact with respect to full evaluation (`core/moat-core/tests/hostname_admission.rs`):
   it never refuses something some resolved address would have allowed, and never resolves when nothing could.
2. **Resolved-address recheck.** Every resolved address is evaluated with the hostname evidence; the first allowed
   one is used. Address rules still apply (a safety deny on the controller wins over an allowed name). A hostname rule
   alone cannot reach loopback, link-local, multicast or unspecified addresses; an address rule must allow those.
3. **The proxy connects to the address it resolved**, never the one the client dialed. Inside a `CONNECT` tunnel, a
   TLS SNI that differs from the `CONNECT` host is refused before the upstream is dialed (#46,
   `a_host_mismatch_inside_a_connect_tunnel_is_refused_before_the_upstream_is_dialed`).
4. **No policy, isolation, or a resource bound reached → refuse.** Connection and resolver bounds
   (`Limits { max_connections: 512, max_lookups: 16 }` per daemon) refuse with a `proxy_limit` event; they never let
   a connection through unchecked.
5. **Snapshot validity.** Admission uses the installed snapshot. An expired or invalid *new* snapshot is rejected at
   install and cannot introduce authority; the last valid snapshot stays enforced and is reported stale
   (`linux.activation.*`, W06).

## 2. Stream: what happens to a connection that was admitted

Every admitted connection is registered (session, hostname evidence, address, admitting rule, admission time) before
any response byte is relayed. A registered stream is **re-evaluated as if it were a new connection at the current
time**, and ended if the answer is no longer *allow*:

| Trigger | When the check runs | Upper bound on stopping delay | CI evidence |
| --- | --- | --- | --- |
| A rule or grant reaches `expires_at` | every daemon tick (`--tick-secs`, default 1 s; the lab uses 1 s) | one tick plus scheduling | netns `W05: stream ended at expiry` |
| A new revision no longer allows it (removed allow, added deny, profile change) | immediately when the revision is installed (`set_policy`), which happens on the tick that picks up the inbox | one tick from the apply request | netns `W05: a revision that no longer allows it ends the open stream` |
| Rollback of a trial to a revision that does not allow it | same as a new revision (rollback installs through the same path) | one tick | unit (same code path); not separately measured |
| Emergency isolation (`moatd recover isolate`) | the tick that observes the recovery state; `set_isolated(true)` ends every stream | one tick | netns `W05: isolation ends open proxied streams` |
| The session ends (its root process exits; descendants are killed) | immediately at session end | immediate | netns `W05: closing the task ends its streams` |
| `moatd` stops (SIGTERM, crash) | process exit closes every proxied socket | immediate | netns `W05: proxied streams end when moatd stops` |
| Policy unchanged, retry or reconnect | a retry is a new admission at the current time; **nothing is renewed** | — | netns `W05: after expiry a new stream is refused` |

How a stream is ended: both sockets are shut down (`shutdown(Both)`) and then closed. The client sees EOF or a reset;
the upstream sees FIN/RST. Bytes already queued in kernel socket buffers at that instant may still be delivered:
**post-decision bytes are bounded by one tick of traffic plus socket buffers, not zero.** Each termination is
spooled as `stream_terminated { session_id, stream, destination, hostname, admitted_by, reason }`.

What is **not** promised:

* **Daemon restart does not adopt streams.** Proxied streams end when `moatd` stops. W06 settled the session side:
  sessions running when the daemon restarts are **stopped, not adopted** (`session_not_adopted`,
  [linux-activation-journal.md](linux-activation-journal.md); decision [#55](https://github.com/robzilla1738/moat/issues/55)).
  Until the new daemon stops them they stay in their profile's chain without a proxy redirect, which is fail-closed.
* **Clock changes.** Expiry is checked against wall-clock UTC on each tick. A wall clock moved backwards delays
  expiry by the same amount; monotonic-deadline handling across reboot is W06/§7.2 work and not claimed here.
* **Plain-HTTP keep-alive** is re-evaluated as a stream (by its first `Host`), not per request.
* **WebSocket** upgrades are streams like any other: admitted once, then ended by the triggers above (unit
  `websocket_upgrade_works_through_connect_and_plain_http_and_is_ended_like_any_stream`; not separately measured in
  netns).
* **Encrypted Host behind an allowed SNI** (fronting) is not detected; it reaches only the allowed name's own server.

Evidence status: claim `linux.session.hostname-proxy`, `implemented_unproven`, native CI only; not the installed unit
and not Omarchy ([STATUS](STATUS.md)).

### Measured (CI netns, linux-endpoint run 40537109945, commit 48f8ee5, 1 s tick)

Receiver-side unless noted: expiry 1.15 s after the deadline; denying revision 0.80 s after the apply request; task
close 0.13 s after the session ended; isolation 0.37 s (client-side EOF); daemon stop 0.11 s after SIGTERM. One run
on a GitHub runner, not a benchmark; the bound to rely on is the table above.

## 3. Direct vs proxied agreement

For traffic without hostname evidence the proxy decides on the original address with the same moat-core
evaluation nftables rules are compiled from. CI compares them on a real kernel with an independent receiver
(`lab-allow` direct vs `lab-mirror` proxied, identical address rules): IPv4 and IPv6, an allowed LAN port, a
safety-denied admin port, and a port with no rule must reach (or not reach) the receiver identically.

## Outside this contract

* **Direct nftables traffic** (profiles without hostname rules, ordinary traffic): nftables evaluates every packet
  (no `ct state established` shortcut), so a ruleset that no longer allows a flow stops its *packets* from the next
  install or expiry re-render on; the connection is not closed cleanly, it stalls. Not separately measured in CI.
* **DNS the workload does itself.** In transparent mode the client may resolve the name before connecting. Whether
  it can is decided by the profile's DNS rules (UDP/TCP 53, the loopback stub resolver, which is a broker — see
  platforms/linux.md). A "no-DNS" profile allows no resolver; workloads then reach names only through the injected
  `HTTPS_PROXY`, where the proxy resolves after authorization.
* **UDP/QUIC** has no hostname evidence and stays with nftables.
* **macOS** (Network Extension) has its own new-flow/active-flow scope (W07, Lane B).
