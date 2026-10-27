# W09 decision: ordinary-app visibility and enforcement on Linux

Status: **decided (observation); enforcement deferred.** Evidence: workflow `w09-experiment`, run
[40545113846](https://github.com/robzilla1738/moat/actions/runs/40545113846), harness commit `859b908`
(`linux/experiments/w09/`), artifact `w09-results` (results.json, sensor.jsonl with process environments redacted,
native.log, OpenSnitch journal and log, nftables rulesets, timestamped trace). Summary table:
[`linux/experiments/w09/results/run-40545113846.md`](../../linux/experiments/w09/results/run-40545113846.md).

> **Follow-up (2026-10-27).** Increment 1 shipped as planned (#30). Increment 2 shipped **observe-only**, with
> bpftrace on `sock:inet_sock_set_state` rather than an eBPF program loaded from Rust (#41,
> [W10 decision](W10-enforcement.md)); UDP is not attributed by that path. The Rust loader (aya + a separate C
> program) was decided in [W10 increment 3](W10-increment-3-loader.md) (#49) and is not built; its licence is
> [#53](https://github.com/robzilla1738/moat/issues/53). Enforcement stays unavailable. The decision below is unchanged.

## Decision

1. **Do not adopt OpenSnitch as Moat's ordinary-app adapter**, read-only or enforcing. Keep the harness so the
   decision can be re-measured against a later OpenSnitch release.
2. **Inventory is native.** W10 ships it in two increments:
   * **Increment 1 (W10, now):** an observe-only collector inside `moatd` that samples the kernel socket tables
     (`/proc/net/{tcp,tcp6,udp,udp6}`), attributes sockets through `/proc/<pid>/fd`, and **counts** what it misses
     from the kernel's own `Tcp: ActiveOpens` counter. No new dependency, no new privilege, no nftables change.
   * **Increment 2 (scheduled, not started):** connect-time attribution in the kernel (eBPF on
     `sock:inet_sock_set_state` and the UDP send path, loaded from Rust), with the ring-buffer overflow counter
     surfaced as loss. W09 measured this hook complete where sampling and OpenSnitch were not.
3. **No ordinary-app enforcement yet.** No app-identity enforcement hook was proven; the existing nftables backend
   keeps rejecting app-scoped rules at compile time (`linux.ordinary-apps.app-rules` stays `unsupported_rejected`).
   The protected-session engine remains the separately described stronger boundary.
4. **One authority.** Moat's inventory never edits another firewall's rules and never becomes a second decider. If a
   user also runs OpenSnitch, both nftables tables coexist (a drop in either wins); Moat claims nothing about
   OpenSnitch's decisions.

## What was measured

Ubuntu 26.04 GitHub runner, kernel 7.0.0-1017-azure x86_64, OpenSnitch 1.8.0 (`.deb` sha256-pinned, `ui.proto`
sha256-pinned, `ProcMonitorMethod: ebpf`, `Firewall: nftables`, `QueueBypass: true`, `DefaultAction: allow`), a
read-only sensor playing the OpenSnitch UI over its gRPC unix socket and answering every AskRule "allow once", and a
native comparison collector (bpftrace on `tracepoint:sock:inet_sock_set_state` for TCP SYN_SENT and kprobes on
`udp_sendmsg`/`udpv6_sendmsg`). Each scenario used its own destination port so records could be matched exactly.

| Scenario | Expected | OpenSnitch records | Native records | Notes |
| --- | --- | --- | --- | --- |
| terminal (curl) | 1 | 1 | 1 | path `/usr/bin/curl`, args, cwd, tree |
| short-lived (200 curl in bursts of 20) | 200 | **184** | 200 | 16 connections never reported, no loss signal |
| interpreter, two scripts | 1 + 1 | 1 + 1 | 1 + 1 | same path `/usr/bin/python3.14`; told apart only by args (`a.py` / `b.py`) |
| executable updated between runs | 1 + 1 | 1 + 1 | 1 + 1 | md5 changed (`process.hash.md5` only) |
| inherited socket (parent creates, child connects) | 1 | 1 | 1 | both attribute to the child that called connect |
| background service (systemd-run, uid nobody) | 1 | 1 | 1 | |
| browser (headless Chrome) | 1 | 4 | 4 | attributed to Chrome's NetworkService utility process, not the tab or profile; process tree empty |
| UDP (5 datagrams, one socket) | 1 flow | 1 | 5 | per-flow vs per-datagram |
| IPv6 | 1 | 1 | 1 | |
| overload (2000 non-blocking connects) | 2000 | **238** | 2000 | queue timeouts in the daemon journal; nothing reached the UI channel as loss (0 alerts) |
| sensor restart (60 HTTP requests across `systemctl restart`) | 60 | **46** | 60 | all 60 requests succeeded: traffic passes unobserved while the daemon restarts |
| sensor stopped (10 HTTP requests) | 10 | **0** | 10 | all 10 succeeded; the `inet opensnitch` table is removed on stop: fail-open, silent |

Fields OpenSnitch populated (of 1224 records): protocol, addresses and ports, pid and executable path in all;
args 1224; cwd 1080; process tree 1140; checksums 1136; destination hostname (DNS correlation) 136; **full process
environment 1052** (tokens and keys included; the harness now redacts it before writing anything).

## The seven W09 questions

1. **Fields available.** OpenSnitch: rich per-connection identity (path, args, cwd, tree, md5, uid, DNS-correlated
   hostname). Native kernel hook: pid, uid, comm, cgroup id, 4-tuple at connect time, every connection; executable
   path and start generation must be resolved from `/proc` (increment 1 does this; increment 2 resolves in-kernel).
2. **Short-lived processes, PID reuse, inherited sockets, interpreters.** OpenSnitch missed 8% of short-lived
   connections and did not say so. Neither tool distinguishes PID reuse by itself; Moat adds the process start
   generation. Inherited sockets are attributed to the connecting process by both. Interpreter apps share an
   executable and differ only in arguments a process can rewrite: identity confidence must be low.
3. **Disconnects, queue loss, stopped sensor, unsupported traffic.** OpenSnitch: queue loss appears only as daemon
   log lines, not on the UI channel; a stopped or restarting daemon lets traffic through (QueueBypass) and reports
   nothing. Native: complete in every scenario; increment 1 turns sampling misses into a counted loss event.
4. **Rule mappings** (see table below).
5. **Ownership, receipts, restart, removal.** OpenSnitch owns `table inet opensnitch` and replaces it on restart;
   while it is down there is no rule and no receipt. Moat would have to supervise a second controller's lifecycle
   to issue credible receipts, against the one-authority rule. Not pursued.
6. **Coexistence.** OpenSnitch's table coexisted with the runner's iptables-nft tables; Moat's `inet moat` table is a
   separate base chain, so a Moat deny still holds while OpenSnitch accepts. Moat's inventory (procfs only) cannot
   conflict with anything.
7. **Packaging, update, license, support.** OpenSnitch daemon is GPL-3.0: talking to it over gRPC as a separate
   process keeps Moat's Apache-2.0 code separate, but bundling it means shipping and updating a GPL package per
   distribution and pinning `ui.proto` per release. Acting as its UI server displaces the user's own
   `opensnitch-ui`. In CI the Python gRPC toolchain pinned for 1.8.0 built from source on Python 3.14 and took
   14.5 minutes. The native increment 1 adds nothing to package; increment 2 adds an eBPF object and a loader crate
   (aya, Apache-2.0/MIT) and needs BTF kernels (Arch/Omarchy kernels ship BTF; to be confirmed on the device).

## Rule mappings for ordinary apps

| Rule shape | Exact mapping available? | Disposition |
| --- | --- | --- |
| per user (uid) allow/deny | yes: nftables `meta skuid` (already rendered) | supported path, existing |
| per executable path | no enforcement hook proven (needs eBPF cgroup/sock_addr connect hooks or an LSM hook with exe resolution) | rejected at compile (unchanged) |
| per systemd app scope / cgroup | partly: `socket cgroupv2` matches a fixed path, app scopes have per-launch suffixes | rejected until a stable-scope design exists |
| per interpreter script | no: the script argument is rewritable | rejected; observation only, low confidence |
| hostname for ordinary apps | no: IP-only outside protected sessions | rejected (allows may opt into skip-with-report) |
| process-instance grant | observation can name instance (pid + start generation); no enforcement hook | rejected for ordinary apps |

## Limits of this experiment

One runner image and kernel, x86_64, everything except the service scenario ran as root, no desktop session, no real
GUI apps, no VPN. The OpenSnitch results apply to 1.8.0 with the configuration above. Omarchy results are required
before any Linux ordinary-app claim moves past `implemented_unproven`.

## What W10 must keep visible

Unknown identity (`identity: null` with a reason), counted TCP loss, unmeasured UDP completeness, other network
namespaces not observed, and the `observe_only` label on every record and in the ledger.
