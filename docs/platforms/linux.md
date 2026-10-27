# Linux endpoint (`moatd`)

`moatd` is Moat's Linux endpoint for Arch/Omarchy and other systemd distributions. It enforces signed policy with
nftables, establishes **protected sessions** in cgroup v2 before the workload executes, keeps a sequenced event spool,
and offers local recovery that works without the controller.

> **Coverage level on Linux:** *protected session* for workloads started with `moat-launch`; *monitoring with
> device/user-wide rules* for everything else. nftables cannot tell ordinary applications apart, so per-app rules are
> not available here and the compiler rejects them for this adapter (or, for allow rules that opt in, leaves them out
> with a report). Hostname rules are IP-only on Linux and are handled the same way.

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
* **Hostname semantics.** nftables sees addresses. Strict hostname allowlists need a policy proxy (planned) and are
  rejected or left out for this adapter rather than approximated.
* **Root, the kernel and the session user's other processes.** A root compromise, a kernel bug, or the same user
  running the workload *outside* `moat-launch` is outside the claim.
* **Interactive terminals without `--pty`.** With `--no-pty` (or when stdin/stdout are not terminals) the session
  receives the caller's descriptors but is not the terminal's foreground process group, so TUIs lose job control.
  With a terminal, `moat-launch` defaults to its **PTY proxy**: it allocates a fresh PTY as the caller, hands the
  slave to the workload as its controlling terminal (`setsid` + `TIOCSCTTY` after the cgroup join and privilege
  drop), and relays bytes and window-size changes from the real terminal. The relay runs outside the session and
  moves terminal bytes only; it opens no sockets. CI checks both behaviors (`netns-enforcement.sh`).

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
