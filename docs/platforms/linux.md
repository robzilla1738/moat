# Linux endpoint (`moatd`)

`moatd` is Moat's Linux endpoint for Arch/Omarchy and other systemd distributions. It enforces signed policy with
nftables, establishes **protected sessions** in cgroup v2 before the workload executes, keeps a sequenced event spool,
and offers local recovery that works without the controller.

> **Coverage level on Linux:** *protected session* for workloads started with `moat-launch`; *monitoring with
> device/user-wide rules* for everything else. nftables cannot tell ordinary applications apart, so per-app rules are
> not available here and the compiler rejects them for this adapter (or, for allow rules that opt in, leaves them out
> with a report). Hostname rules for ordinary traffic are IP-only and handled the same way; **inside protected
> sessions** they are enforced for TCP by the session egress proxy (TLS SNI / HTTP CONNECT / HTTP Host, no TLS
> interception; see below). The proxy is implemented and checked in CI on a real kernel, and stays labelled
> *untested* until it has run on Omarchy.

## Install

Arch / Omarchy (packaging path, unsigned until you sign it with your own key):

```sh
cd linux/packaging/arch && makepkg -si
sudo moatd trust /path/to/signer.key.pub     # the policy signer's PUBLIC key
sudo systemctl enable --now moatd
moatd capabilities                            # what this host can really do
```

From source: `cargo build --release -p moatd -p moatctl`, then install `moatd`, `moat-launch`, `moatctl` and
`linux/packaging/systemd/moatd.service`.

## Policy delivery

`moatd` only installs **signed** snapshots from a trusted signer key (`/var/lib/moat/trusted/*.pub`). Delivery is a
file drop: `sudo moatd apply signed.json` copies a snapshot into `/var/lib/moat/inbox/`; the controller's sync agent
uses the same inbox. Every snapshot is verified (signature, platform, replay, expiry, schema), rendered and
syntax-checked with `nft -c` before one atomic `nft -f` transaction replaces the previous table. Any failure keeps the
last working revision and records the reason (`moatd status`, spool `policy_rejected`).

When the controller is unreachable the last valid policy stays in force, including across reboots: the daemon
re-verifies `/var/lib/moat/current.signed.json` at startup. An expired snapshot keeps being enforced (dropping to no
policy would be weaker) and is reported as stale.

## Protected sessions

```sh
moat-launch --profile coding-session -- claude
```

What happens, in order, between fork and exec of the workload:

1. it joins `/sys/fs/cgroup/moat.slice/p-<profile>/s-<session-id>` while the supervisor is still root;
2. in a private mount namespace, the user's runtime dir (`/run/user/<uid>`: systemd `--user`, session D-Bus),
   Docker/Podman/containerd sockets and the SSH agent socket are hidden (`--allow-brokers` keeps them, weakening the
   boundary); `DBUS_SESSION_BUS_ADDRESS`, `SSH_AUTH_SOCK`, `DOCKER_HOST`, `LD_PRELOAD` and `LD_LIBRARY_PATH` are removed;
3. supplementary groups, gid and uid are dropped to the **caller's** identity, taken from `SO_PEERCRED`;
4. `no_new_privs` is set, so setuid helpers (`sudo`, `pkexec`) cannot regain privileges;
5. every inherited descriptor above stderr is marked close-on-exec, so no preexisting socket crosses in;
6. the argv is executed directly. There is no shell and no command string.

nftables matches the session by cgroup ancestry (`socket cgroupv2 level 2 "moat.slice/p-<profile>"`), so every child,
grandchild and detached process inherits the session's rules. A process found anywhere under `moat.slice` without a
known profile is rejected.

**Self-escape.** Moving a process between cgroups requires write access to the common ancestor's `cgroup.procs`. All
Moat cgroups and the cgroup root are root-owned, the workload runs as a non-root user with `no_new_privs`, and root
workloads are refused. `linux/moatd/tests/privileged.rs` verifies placement-before-exec, inheritance, failed escape
writes, uid/group drop, `no_new_privs`, descriptor isolation, broker hiding and session teardown on a real kernel.

**Session lifetime.** A session ends with its root process; remaining descendants (including `setsid` daemons) are
killed through `cgroup.kill`, so nothing keeps running unattributed.

**Refusals.** `moat-launch` exits 126 with a reason when there is no valid policy, the profile is unknown or not
available on this platform, enforcement is disabled locally, the host cannot enforce sessions (no cgroup v2, no
nf_tables, no `socket cgroupv2`), or the caller is root. It never falls back to running unprotected, and exits 125 if
the daemon is unreachable.

### What a Linux protected session does **not** cover

Stated so nobody infers a stronger claim:

* **Abstract-namespace Unix sockets** (`@/tmp/.X11-unix/X0`, some D-Bus brokers) belong to the network namespace and
  are not hidden by the mount namespace. A broker listening there can act outside the session.
* **The system DNS resolver** (`systemd-resolved` on 127.0.0.53) is a broker: lookups are made by the resolver's own
  cgroup. Allowing loopback DNS lets a session leak data through DNS queries. Allow resolvers deliberately, or route
  sessions to a filtering resolver.
* **Brokers reachable by a path the profile does not hide** (a local HTTP proxy, a browser's remote-debugging port on
  loopback, a database on loopback). Loopback allows in a profile reach them.
* **Hostname semantics.** nftables sees addresses. Hostname rules are enforced only for TCP inside protected sessions,
  by the session egress proxy, from what the client puts on the wire (SNI, CONNECT target, first Host header). See
  [the proxy's limits](#session-egress-proxy-hostname-rules-in-protected-sessions). Outside sessions, hostname rules
  are rejected or (allows that opt in) left out with a report.
* **Root, the kernel and the session user's other processes.** A root compromise, a kernel bug, or the same user
  running the workload *outside* `moat-launch` is outside the claim.
* **Interactive terminals without `--pty`.** With `--no-pty` (or when stdin/stdout are not terminals) the session
  receives the caller's descriptors but is not the terminal's foreground process group, so TUIs lose job control.
  With a terminal, `moat-launch` defaults to its **PTY proxy**: it allocates a fresh PTY as the caller, hands the
  slave to the workload as its controlling terminal (`setsid` + `TIOCSCTTY` after the cgroup join and privilege
  drop), and relays bytes and window-size changes from the real terminal. The relay runs outside the session and
  moves terminal bytes only; it opens no sockets. CI checks both behaviors (`netns-enforcement.sh`).

## Trial revisions (timed rollback)

A revision can be installed on trial. Unless you confirm it on the device before the deadline, `moatd` reinstalls the
last confirmed revision by itself. This matches the macOS canary.

```sh
sudo moatd apply signed.json --trial-secs 600   # enforce now, revert in 10 minutes unless confirmed
sudo moatd recover confirm                      # keep it (works with the daemon stopped, too)
sudo moatd recover rollback                     # revert now
moatd recover status                            # shows the pending trial and its deadline
```

* A trial needs a confirmed revision to fall back to. The first policy on a device cannot be a trial: falling back to
  "no policy" would remove enforcement, so it is refused.
* The fallback is the device's own stored copy of the last confirmed snapshot. Its signature is checked again before
  it is reinstalled. The replay high-water mark stays at the trial revision, so the reverted revision cannot be
  replayed from the network. To move on, publish a newer revision.
* Rollback never touches local isolation or the local disable switch.
* Applying another revision without `--trial-secs` ends a pending trial; the new revision counts as confirmed.
* **Limit:** the countdown is enforced by the running daemon. If `moatd` is stopped past the deadline, the trial
  revision stays in the kernel until `moatd` starts again, and is reverted on that start.
* Spool events: `policy_trial_started`, `policy_trial_confirmed`, `policy_rolled_back` (plus a `policy_applied`
  receipt with `rollback_of`), `policy_rollback_failed`. The controller records them per device and raises an
  attention item for every rollback.

CI checks this on a real kernel: a deliberately broken trial revision is enforced, reverts on its own, cannot be
replayed, and a confirmed trial stays (`netns-enforcement.sh`).

## Session egress proxy (hostname rules in protected sessions)

Profiles with session-scoped hostname rules (for example `coding-session` allowing `api.github.com`) send their TCP
through a per-session proxy inside `moatd`. Profiles without hostname rules are not proxied and stay pure nftables.

How it works, exactly:

1. Before the workload starts, `moatd` opens a listener for the session on loopback (default ports 15000–15999) and
   installs an nftables `redirect` that matches **only that session's cgroup**. Every TCP connection the session makes
   to a non-loopback address goes to its listener. `HTTPS_PROXY`/`HTTP_PROXY` are also set, so tools that honour them
   use `CONNECT` on the same listener.
2. The proxy reads only the start of the connection: the TLS ClientHello (for the SNI), the `CONNECT` request line,
   or the plain-HTTP request header (for `Host`). It never decrypts, never terminates TLS, never presents a
   certificate.
3. It resolves the name itself and connects to the address **it** resolved, on the original port. It never connects
   to the address the client dialed. A spoofed SNI therefore reaches the real host of that name.
4. Every candidate address is evaluated with moat-core together with the hostname evidence (`sni`, `connect_proxy`
   or `http_host`, confidence *medium*). Address rules still apply, so a safety deny on the controller wins even when
   an allowed name resolves to it.
5. Connections with no hostname (TLS without SNI, server-speaks-first protocols after a 1.5 s wait, anything else)
   are evaluated on the original address only, so hostname allows cannot match them.
6. Each decision is spooled as a `flow` event with the hostname source and, when they differ, the address the client
   dialed (`client_dialed`). Refused `CONNECT` and plain-HTTP requests get an explicit `403` from the proxy; refused TLS
   is closed.
7. A session can reach only its own listener. nftables rejects every other use of the proxy port range, so a session
   cannot borrow another session's grants. The proxy's upstream sockets carry a mark that only root can set, and
   only those are accepted ahead of the ordinary-traffic rules. Local isolation still applies to them.

What it does **not** do:

* **UDP/QUIC has no hostname evidence here.** UDP stays with nftables. The compiler therefore refuses a session
  hostname **deny** unless it is `transport = "tcp"` (otherwise it would silently miss UDP). A hostname **allow** on
  any transport is enforced for TCP only, which is stricter, and the compile report says so.
* **No path, method or repository restrictions.** Only the name and port are checked.
* **Plain-HTTP keep-alive:** only the first request's `Host` is checked.
* **Encrypted ClientHello** exposes only its public outer name, and that is the name evaluated.
* **Domain fronting** through an allowed host's CDN remains possible.
* **DNS:** in transparent mode the client still resolves names itself (through the system resolver, a broker; see
  above). With `HTTPS_PROXY` the proxy does the resolving, and only **after** authorizing the name: a name no rule
  can allow is refused without any lookup.

**Admission vs open streams.** Admitted streams are registered and re-checked on every policy install and every
daemon tick; expiry, a revision that no longer allows them, isolation, session end and daemon stop each end them.
The full contract, with stopping bounds and what is not promised, is [proxy-stream-contract.md](../proxy-stream-contract.md).

Turn it off with `moatd run --no-egress-proxy`. The capability probe also turns it off when the kernel lacks nftables
nat `redirect`. With the proxy off, hostname rules in sessions behave as on an IP-only host (`--adapter linux-ip-only`
in `moatctl`). The capability is advertised as `session_hostname_proxy: untested` until it has run on Omarchy.

CI (`netns-enforcement.sh`) checks it on a real kernel with a TLS lab: an allowed SNI reaches the real host; a
denied SNI is blocked; a spoofed SNI aimed at another address still lands on the resolved host; `CONNECT` through the
injected `HTTPS_PROXY` works and refuses unlisted hosts; plain HTTP is decided by `Host`, and refusals get a `403`;
TLS to a bare IP (no SNI) is blocked; another process cannot use a session's listener; decisions reach the spool. W05 adds: a forbidden name produces no query at the lab resolver (positive control: the allowed name does); direct
and proxied enforcement agree at an independent receiver over IPv4/IPv6; and a long-lived TLS stream is ended at
expiry, by a revision that no longer allows it, by task close, by isolation and by daemon stop, with the measured
stopping delay printed in the CI log.

## Ordinary traffic

Traffic outside protected sessions follows device-wide and per-user rules (`meta skuid`) and then the fallback
profile. With the default `ordinary-desktop-learning` profile it is **observed: permitted, not enforced**, and the UI
says so. Counters are per rule, not per flow, and are reported with `scope: "rule"`.

## Capabilities

`moatd capabilities` starts from the declared contract and only ever downgrades it:

| Probe fails | Downgraded |
| --- | --- |
| no `nft` binary, or nf_tables unusable | every enforcing capability |
| no cgroup v2 | protected-session enforcement |
| `socket cgroupv2` rejected by `nft -c` | protected-session enforcement |

## Event spool

`/var/lib/moat/spool/seg-*.jsonl`, append-only, 256 MiB quota by default (`--spool-mib`). Every record has a
per-device sequence number. Each start writes a `restart` record saying whether the previous run shut down cleanly.
When the quota is reached, events are dropped and a `gap` record states the exact lost range once space returns.
Enforcement never waits for or depends on the spool.

## Local recovery

All recovery is local and root-only, and works with the daemon stopped:

```sh
sudo moatd recover status
sudo moatd recover disable --reason "broke ssh"   # removes the Moat table; protected sessions refused
sudo moatd recover resume                         # last valid policy is re-applied on the next tick
sudo moatd recover isolate --keep 100.100.1.2/32  # whole-device isolation except loopback + chosen paths
sudo moatd recover clear-isolation
```

Isolation lives in its own table. A new policy, a daemon restart or a missing controller heartbeat never reopens it;
only `clear-isolation` does. If either Moat table is removed outside Moat, the daemon restores it and records that.

Uninstall: `sudo systemctl disable --now moatd && sudo nft delete table inet moat; sudo nft delete table inet
moat_local_emergency`, then remove the package. The Arch package's `pre_remove` hook does this for you.

## Tests

| Test | Where it runs | What it proves |
| --- | --- | --- |
| `cargo test -p moatd` | anywhere | rendering, precedence order, scope tables vs `classify`, spool, recovery, endpoint state machine |
| `tests/privileged.rs` | CI (ubuntu-latest, root) and any cgroup v2 host | boundary mechanics on a real kernel |
| `linux/tests/netns-enforcement.sh` | CI (ubuntu-latest, root, nf_tables) | real packets: allow, deny, safety precedence, IPv6, UDP, grandchildren, escape attempts, refusal, replay, recovery, isolation stickiness, offline restart |

These run on GitHub's Ubuntu kernel, **not yet on Omarchy**. Robert's Arch/Omarchy kernel, systemd and network stack
are on the [device-proof list](../STATUS.md).
