# Decision for Robert: `CAP_SYS_PTRACE` in the packaged moatd unit (W11)

Status: **open, needs Robert** ([#54](https://github.com/robzilla1738/moat/issues/54)). The unit merged with W11 keeps `CAP_SYS_PTRACE` so installed workloads can write
their project. This page records why, what it costs, and the alternative that would let us drop it.

## Problem

`moatd.service` runs the daemon with `ProtectSystem=strict`, `ProtectHome=read-only` and `PrivateTmp=yes`. systemd
gives the daemon a private mount namespace in which `$HOME` is read-only and `/tmp` is private. A protected
workload is forked by `moatd`, so before W11 it inherited that namespace and could not edit its project
(`D-SYSTEMD-WORKSPACE`).

W11 fixes it in `linux/moatd/src/launch.rs`: between fork and exec the child opens the session's `cgroup.procs`
(in the daemon's namespace, so nothing in the user's namespace can redirect the join), then `setns()`s into PID 1's
mount namespace and re-enters its working directory, then continues as before (cgroup join, broker hiding,
privilege drop). The daemon itself stays sandboxed.

To get PID 1's namespace the daemon opens `/proc/1/ns/mnt`. That is a ptrace-mode access check; with the unit's
reduced capability bounding set it fails without `CAP_SYS_PTRACE`. `setns(CLONE_NEWNS)` also needs
`CAP_SYS_ADMIN` (already present) and `CAP_SYS_CHROOT` (added).

Evidence: CI job "installed systemd unit (W11)" (`linux/tests/installed-unit.sh`) installs the packaged unit on a
GitHub Ubuntu runner, starts it with `systemctl`, and checks that a real non-root user's workload writes its project
under `$HOME` and the real `/tmp`, owns its files, and still fails the egress, cgroup-escape and broader-nested-launch
probes, including after `systemctl restart`. That is an Ubuntu runner, **not** the Arch package on Omarchy;
`linux.packaging.systemd` stays `unknown_degraded` until it runs there.

## What `CAP_SYS_PTRACE` costs

* If `moatd` is compromised, the attacker can ptrace (read and write the memory of) any process on the host,
  including the user's browser, password manager and SSH agent, without a further exploit.
* Honest scale: `moatd` already runs as root with `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE` and
  `CAP_SETUID`. A compromised `moatd` is close to full root already, so `CAP_SYS_PTRACE` widens an already large
  blast radius rather than creating one. It still removes one more obstacle and is a capability a reviewer will flag.
* `NoNewPrivileges=no` and `RestrictNamespaces=no` were already required by the launcher; unchanged by W11.

## Alternative: pass the caller's mount namespace over the control socket

`moat-launch` runs as the user, in the user's own mount namespace. It can hand that namespace to the daemon with no
extra privilege:

1. `moat-launch` opens `/proc/self/ns/mnt` (always allowed for one's own process) and sends the descriptor with the
   launch request as `SCM_RIGHTS` ancillary data on the existing Unix control socket.
2. `moatd` validates the descriptor before using it:
   * `ioctl(fd, NS_GET_NSTYPE) == CLONE_NEWNS` (it is a mount namespace, not some other file);
   * `ioctl(fd, NS_GET_USERNS)` is the initial user namespace (compare `st_dev`/`st_ino` with the daemon's own
     `/proc/self/ns/user`), so a namespace the user built inside an unprivileged user namespace, with a forged
     `/etc` or `/usr`, is refused;
   * the request is otherwise authorized exactly as today (kernel-attested `SO_PEERCRED` caller, W04 containment
     check: a contained caller still gets at most its own profile).
3. The child does what W11 does now, with the passed descriptor instead of `/proc/1/ns/mnt`.

Effect: `CAP_SYS_PTRACE` leaves the bounding set (`CAP_SYS_CHROOT` stays: `setns` needs it). The workload sees the
caller's own filesystem view, which is arguably more correct than PID 1's (for example, a user working inside a
toolbox or a separate mount namespace gets the project they launched from).

Cost and risk:

* A protocol change on the control socket (new optional ancillary data, a version bump, a refusal when it is
  absent under a sandboxed daemon) plus validation code in the most security-sensitive path.
* A contained task could pass a namespace too. It already runs in a mount namespace derived from its launcher's, and
  the W04 rule (own profile at most) still decides the profile; the namespace never chooses network policy. That
  argument needs its own regression test (a contained caller passing a namespace it created with `unshare -m`
  must not gain a filesystem view that unhides the brokers it was denied).
* Estimated at one to two focused days including the netns and installed-unit tests.

## Options

| Option | Keeps `CAP_SYS_PTRACE` | Work | Notes |
| --- | --- | --- | --- |
| A. Keep W11 as merged | yes | none | Proven in CI on the installed unit; widen blast radius of a moatd compromise. |
| B. Pass the namespace over the socket | no | 1–2 days | Smaller bounding set; caller's own view; new validation path to review. |
| C. Drop `ProtectHome`/`PrivateTmp` from the unit | no | small | Workloads inherit a writable view, but the daemon loses its own filesystem sandbox. Not recommended. |

Recommendation: **B**, scheduled after the Omarchy installed run, because the Omarchy result may change the unit
anyway. Until Robert decides, A stays in place and this page is the record.
