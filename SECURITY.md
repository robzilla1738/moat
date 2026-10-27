# Security policy

Moat is an **experimental build** (see [docs/STATUS.md](docs/STATUS.md)). Nothing in it is `supported_installed`
yet, so do not rely on it as your only protection. Reports are still very welcome, especially about the trust
boundaries listed below.

## Reporting a vulnerability

* **Use GitHub's private vulnerability reporting**: the repository's *Security* tab → *Report a vulnerability*.
  This opens a private advisory visible only to the maintainer.
* Please **do not** open a public issue, pull request or discussion for a suspected vulnerability.
* Include: the affected component and commit, the platform and version (OS, kernel, macOS build), what you expected
  Moat to enforce, what it did instead, and the smallest reproduction you have (a policy file and commands are ideal).

What to expect: an acknowledgement within 7 days, an initial assessment within 14 days, and credit in the advisory
and release notes unless you ask otherwise. Moat is maintained by one person; these are intentions, not an SLA.

## What counts

The highest-value reports concern Moat's authority and enforcement boundaries:

| Boundary | Where |
| --- | --- |
| Policy signing and verification, replay and rollback protection | `core/moat-core/src/signing.rs`, `core/moat-core/src/revision.rs`, `controller/src/signer*.ts` |
| Compiler and structured diff (an approval authorizing more than it showed) | `core/moat-core/src/compile.rs`, `diff.rs`, `grants.rs` |
| Privileged launcher and session containment on Linux (cgroup, nftables, egress proxy) | `linux/moatd/src/launch.rs`, `bin/moat-launch.rs`, `caller.rs`, `nft.rs`, `proxy.rs` |
| Native control APIs (control socket, FFI, Mac XPC/system extension) | `linux/moatd/src/control.rs`, `server.rs`, `core/moat-ffi`, `macos/MoatKit`, `macos/Moat/Extension` |
| False status: the UI, API or ledger saying "applied" or "protected" when the endpoint did not commit or enforce it | anywhere |

A documented limit (for example domain fronting through a shared CDN, or ordinary-app rules on Linux being
unsupported) is not a vulnerability by itself; a way around a limit that is **claimed** to hold is. The claimed
scope is [docs/STATUS.md](docs/STATUS.md) and [docs/support-matrix.md](docs/support-matrix.md).

## Supported versions

Only experimental prereleases exist (`v0.1.0-alpha.*`), and no version is supported. Fixes land on `main` and in
the next prerelease; there are no backports. Supported versions and their end of support will be listed in
[docs/support-matrix.md](docs/support-matrix.md). Release assets can be checked with
`release/recovery-drill.sh integrity <dir>` ([docs/recovery-drill.md](docs/recovery-drill.md)).

## Maintainer setup still needed

Private vulnerability reporting must be enabled in the repository settings (*Settings → Code security*;
[#51](https://github.com/robzilla1738/moat/issues/51)). Until it is, the *Report a vulnerability* button does not
appear; open a minimal public issue that says only "security
report, please contact me" and the maintainer will reach out privately.
