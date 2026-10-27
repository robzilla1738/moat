# Compatibility and adversarial test suite

Two suites. The **compatibility suite** proves Moat does not break the workflows Robert depends on. The
**adversarial-but-benign suite** probes bypasses with controlled destinations and canary data. Some adversarial cases
exist to *document a limitation* rather than to pass: Moat is not DLP.

**Status: no device row has run** ([#11](https://github.com/robzilla1738/moat/issues/11)). Everything automated runs
on GitHub CI runners: policy conformance (`conformance/cases`, run by `moatctl conformance` and
`core/moat-core/tests/conformance.rs`), the Linux netns suite (`linux/tests/netns-enforcement.sh`), the installed-unit
check, the ordinary-app inventory checks, privileged cgroup tests, MoatKit unit tests, controller and web tests, and
the CI part of the [recovery drill](recovery-drill.md). Results from a CI kernel or an unsigned macOS runner are not
evidence about Robert's machines. The release gate that needs this suite is **G4** (declared compatibility matrix,
30-day workflow pilot; MASTER_ROADMAP §11.1, §13).

## A. Workflow compatibility (acceptance: G4, a 30-day pilot)

Roll out on the M1 Pro first, then the other laptop and Arch, the mini last. Protect workloads before any
whole-device lockdown.

| Workflow | Exercise | Policy design | Status |
| --- | --- | --- | --- |
| Tailscale + SSH | MagicDNS and IP access, new and existing sessions, direct/relay, reconnect, sleep/wake, exit nodes | Narrow transport/control permissions, named management peers, local recovery proven ([VPN matrix](vpn-test-matrix.md)) | device ☐ |
| Plex | Local and remote playback, login, discovery, metadata, updates, transcoding | Own service profile; do not assume LAN-only | device ☐ |
| BlueBubbles | Messaging, attachments, background delivery, reconnect, server reboot | Own profile; Firebase notification dependency means a whole-device block affects it | device ☐ |
| adb to the TV | Real pairing mode (USB / wireless), reconnection, discovery | Learn the real ports; wireless adb uses discovery + paired services, not a fixed 5555 | device ☐ |
| Agent development | Provider login, git fetch/push, package installs, test servers, remote tools, generated executables | Service packs (`packs/services`), the maintained coding workflow pack (`packs/workflows`, W14) and bounded grants (W03); brokered and cloud execution labelled. Restarting `moatd` stops running sessions ([#55](https://github.com/robzilla1738/moat/issues/55)). | device ☐ |
| Controller + DNS | Reboot, power/network loss, disk pressure, policy rollback | Endpoint offline operation, bounded spools with declared gaps (W13), resolver health and backoff (W16) | partly CI (netns offline restart, controller sync-outage tests, recovery drill); device ☐ |
| Streaming (TV) | Auth, ads, CDN rotation, casting | DNS blocklists expanded only after testing; DNS-only coverage ([#9](https://github.com/robzilla1738/moat/issues/9)) | device ☐ |

Keep a running list of observed incompatibilities next to this table. None has been recorded yet because no device
run has happened.

## B. Adversarial-but-benign suite

The canonical, test-by-test mapping is the [adversarial matrix](adversarial-matrix.md) (MASTER_ROADMAP §15.2). Its
machine-readable copy is the `adversarial_matrix` array in [`claim-ledger.json`](claim-ledger.json), checked by
`core/moat-core/tests/claim_ledger.rs`: every `ci` row names tests that exist. This page does not repeat it, so the
two cannot disagree.

In summary, CI covers on Linux: direct IP, IPv4/IPv6, UDP, alternate resolvers, DNS before deny, SNI/Host spoofing and
a visible `CONNECT` host vs SNI mismatch, redirects judged anew, long-lived TLS/`CONNECT`/WebSocket streams ended on
expiry, revision, isolation, task end and daemon stop, fork/exec chains and detached processes, pre-opened sockets,
cgroup self-escape, broker hiding, weaker nested launches, disk full, slow disk, corrupt and newer-schema state,
crash during rollback, live-task restart, log quota, proxy exhaustion and notification floods. macOS rows run as
unsigned unit tests only.

Rows that remain **device-only** (none has run):

| Case | Expected | Platform |
| --- | --- | --- |
| QUIC to a denied destination | Blocked unless allowed | Linux sessions, macOS |
| SSH agent forwarding / ProxyJump from a session | Broker hidden or labelled unresolved | Linux |
| Browser automation over CDP from a session | Labelled; no silent claim | Linux |
| Docker daemon and remote jobs launched from a session | Coverage labelled | Linux |
| Abstract Unix socket broker | **Documented limitation** | Linux |
| Allowed provider used to write data (e.g. GitHub API gist) | **Documented limitation**: allowed | both |
| Active stream during a policy change on macOS | Measure bytes before revocation; no revocation claim | macOS |
| Filter/daemon crash and restart; package or cask upgrade; clean uninstall | Coverage reported; no fail-closed claim; nothing left behind | both |
| Every case above on the signed Mac and on Omarchy | Same results as CI, recorded with versions | both |
| VPN variants, sleep/wake, network switch, Plex/BlueBubbles/SSH, the real TV and adb | See section A and the VPN matrix | both |

The device-only harness lives in `tests/adversarial/` (see its README). It refuses to run in CI or without an
explicit canary URL, because results from a CI kernel are not evidence about Robert's machines.
