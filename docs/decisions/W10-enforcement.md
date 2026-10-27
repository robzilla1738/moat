# W10 decision: ordinary-app enforcement on Linux stays unavailable (2026-10-27)

**Status:** decided for now; revisit when a hook below is proven.
**Scope:** per-application (executable-identity) rules for ordinary Linux apps, i.e. apps not started by
`moat-launch`. Protected sessions are a separate, proven boundary (cgroup v2 + nftables) and are unaffected.

## What increment 2 delivers

Observation only: connect-time attribution through `tracepoint:sock:inet_sock_set_state` loaded by bpftrace
(`linux/moatd/src/ebpf.rs`, `moatd inventory --ebpf`, `moatd run --ordinary-inventory-bpftrace`). Loss (buffer
overflow, stalls, tracer exit, unparsed lines) is reported as `inventory_loss`. CI evidence:
`linux/tests/ordinary-inventory-ebpf.sh` against an independent receiver and the kernel's ActiveOpens counter.

## Why enforcement is not offered

A supported app rule needs a hook that (1) decides at connect time in the kernel, (2) keys on an identity the app
cannot forge, and (3) can be shown in CI netns to stop traffic an independent receiver would otherwise see. None of
the candidates meets all three with what Moat ships today:

| Hook | Decides in kernel | Unforgeable identity | Status |
|---|---|---|---|
| nftables `meta skuid` / `socket cgroupv2` | yes | uid / cgroup only, not executable | Already used for sessions; an ordinary app is not in a Moat cgroup, so this is not an app rule. |
| nftables `meta cgroup` + moving apps into cgroups by name | yes | no: placement by name or comm is spoofable and racy (the app connects before it is moved) | Rejected. |
| cgroup/connect4,6 BPF program keyed on the task's `mm->exe_file` inode + device | yes | strong (file identity, not a name) | Needs a BPF loader in moatd (aya/libbpf), CO-RE/BTF, map lifecycle and pinning, and a defined behavior for exec-after-connect, inherited sockets and interpreters. Not built; not proven. |
| bpftrace `system()`/signals as a reaction | no (after the fact) | n/a | Not enforcement: bytes already left. Rejected. |
| LSM BPF `socket_connect` | yes | strong | Requires `lsm=…,bpf` on the kernel command line; not enabled on ubuntu-latest or stock Omarchy. Not provable in CI. |

## What remains true

* `linux.ordinary-apps.app-rules` stays `unsupported_rejected`: app rules are refused at compile; allows that opt in
  are omitted with a report.
* Coverage labels say `observe_only` for every ordinary-app record.

## What would change this

A cgroup/connect BPF program loaded by moatd, keyed on executable file identity, with a netns CI check that a denied
executable's connect never reaches the receiver while an allowed one does, plus the exec/inheritance/interpreter
cases in docs/adversarial-matrix.md. That is W10 increment 3 and needs a loader dependency decision (aya vs libbpf-rs).
