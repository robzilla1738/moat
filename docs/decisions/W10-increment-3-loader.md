# W10 increment 3 decision: BPF loader for a cgroup/connect hook keyed on executable file identity (2026-10-27)

**Status:** loader chosen (aya for userspace, the program in C built by clang); **hook not built, enforcement stays
unavailable.** `linux.ordinary-apps.app-rules` remains `unsupported_rejected`.
**Follows:** [W10-enforcement.md](W10-enforcement.md), which names the cgroup/connect hook as the only candidate that
decides in the kernel, keys on an identity the app cannot forge, and could be proven in CI netns.

## The hook this loader has to carry

A `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program attached at `connect4`/`connect6` (and `sendmsg4`/`sendmsg6` if UDP is
ever claimed) on the root cgroup, so it sees ordinary apps that `moat-launch` never placed. For each connect it:

1. derives the caller's executable file identity, `(st_dev, st_ino)` of the task's `mm->exe_file` (plus the inode
   generation or change time where available, so a replaced file is a different identity);
2. looks that identity up in a map moatd fills from the compiled policy (`identity -> allow/deny + destination set`);
3. returns `0` (reject, the caller sees `EPERM`) or `1` (allow), and emits a ring-buffer record of the decision.

Two ways to get step 1, to be settled by the prototype:

* **A. Read the task in the connect hook.** `bpf_get_current_task_btf()` then `task->mm->exe_file->f_inode`.
  Needs the helper to be callable from cgroup sock_addr programs on the target kernels and needs CO-RE
  relocations for `task_struct`, `mm_struct`, `file`, `inode`. Simplest semantics, no extra state.
* **B. Track exec, look up at connect.** A `tp_btf/sched_process_exec` (or `lsm/bprm_committed_creds` where BPF LSM
  is on) program records `tgid -> identity` from `bprm->file`; the connect hook looks up `bpf_get_current_pid_tgid()`.
  Works with only the helpers every program type has, but adds a map whose lifetime must follow fork/exit and a
  defined answer for processes that existed before moatd started (they are unknown, and unknown must deny for a
  deny-by-default app profile and allow-with-report otherwise).

Either way the following stay open and must be tests, not prose: exec after connect (an fd opened by one binary
used after `execve` of another), sockets inherited across fork/exec or passed over `SCM_RIGHTS`, interpreters (every
Python script is `/usr/bin/python3`; script identity is not available in kernel and must be reported as a limit),
binaries on overlay/FUSE filesystems where `(dev, ino)` is not stable, and `connect()` on a socket whose
destination is later changed by `sendto`.

## Options compared

| | **aya** | **libbpf-rs** (+ libbpf-cargo) |
|---|---|---|
| Userspace | Pure Rust loader; no C library linked into moatd | Rust bindings over libbpf (C, vendored through libbpf-sys) |
| Native build deps of moatd | none beyond Rust | libbpf, libelf, zlib (vendored or system); `pkg-config` |
| BPF program language | Rust (`aya-ebpf`, nightly + `bpf-linker`) **or** a C object built by clang | C, built by clang via `libbpf-cargo` skeleton generation |
| CO-RE for kernel structs | Loader applies BTF relocations from a C-built object. As of this writing, rustc does not emit `preserve_access_index` relocations for Rust-written programs as clang does for C, so option A written in Rust would depend on per-kernel generated bindings (to be re-checked against current aya before building). | Mature: libbpf is the reference CO-RE implementation |
| cgroup sock_addr attach + link pinning | Supported (`CgroupSockAddr`, link pinning under bpffs) | Supported |
| Licence of the loader | MIT OR Apache-2.0 | libbpf-rs / libbpf: LGPL-2.1 OR BSD-2-Clause (BSD-2 can be chosen) |
| Static/musl moatd builds | Straightforward | Possible with vendoring; more moving parts |
| Who else ships it | Used by several Rust network/observability daemons | Used widely; libbpf is what bpftool and most C tools use |

## Decision

**aya as the loader in moatd; the program itself written in C, compiled by clang with CO-RE, and loaded by aya.**

* moatd keeps a pure-Rust dependency tree with no C library in the privileged daemon, which matters more for a
  security-boundary process than the convenience of skeletons.
* Writing the program in C sidesteps the one real weakness of aya for this hook (no CO-RE from Rust-written
  programs), which option A depends on. aya applies the relocations clang emits.
* The BPF object is a separate artifact under `linux/bpf/` with its own licence header. Reading `task->mm` uses
  helpers the kernel marks GPL-only (`bpf_probe_read_kernel`, `bpf_get_current_task_btf`), so the object's
  `license` section must be GPL-compatible (conventionally `"Dual BSD/GPL"`). That object is data loaded into the
  kernel, not linked into the Apache-2.0 Rust crates, but it is a **licensing decision for Robert** before it ships
  (see [licensing.md](../licensing.md)); the CI licence report treats `linux/bpf/` separately.
* The feature is behind a cargo feature (`ebpf-enforce`), off by default, and the compiler keeps rejecting app rules
  unless the endpoint reports a proven hook at runtime. No build of moatd claims it because the code is present.

libbpf-rs remains the fallback if aya's handling of the chosen helpers or relocations fails in CI; the program in C
would carry over unchanged.

## Why no prototype in this wave

The assignment allowed a prototype only if it could be proven in CI netns against an independent receiver. Not done
in this wave, for these reasons, stated rather than worked around:

* The development sandbox cannot load BPF programs at all (bpftrace's `BEGIN` probe fails to load there), so every
  verifier iteration would be a CI round trip of ~5 minutes; the hook's correctness depends on verifier and helper
  behaviour on the runner kernel that cannot be checked locally.
* A credible proof is more than "a denied binary's connect is refused": it needs the exec/inheritance/interpreter
  cases above, two binaries with identical names but different files, a replaced binary, and the receiver seeing
  zero bytes from the denied one while an allowed one is accepted. That is a work package, not a spike.
* W10 increment 2 (connect-time observation) had to be made green first; its attach-time failure is the same class
  of runner-kernel dependency this hook will have.

## Proof required before any app rule is offered

A CI job in `linux-endpoint.yml` (netns lab, independent receiver, like `ordinary-inventory-ebpf.sh`) that shows:

1. a denied executable's TCP connect is refused (`EPERM`) and the receiver accepts **nothing** from it;
2. an allowed executable with the **same file name** in another directory connects and is accepted;
3. replacing a binary in place changes its identity (the old allow does not carry over);
4. a socket connected by an allowed binary and inherited across `execve` into a denied one is reported (this is a
   known escape for connect-time hooks; it must be a documented limit or blocked by `sendmsg` hooks);
5. detaching the program (moatd stop, crash) is reported as coverage lost, never as still enforcing;
6. the claim ledger row cites that run, and the disposition is still at most `implemented_unproven` until it runs
   on Robert's installed Omarchy machine.

Until then: compile rejects app rules on Linux, records say `observe_only`, and STATUS says so.
