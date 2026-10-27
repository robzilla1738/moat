# Compatibility and adversarial test suite

Two suites. The **compatibility suite** proves Moat does not break the workflows Robert depends on. The
**adversarial-but-benign suite** probes bypasses with controlled destinations and canary data. Some adversarial cases
exist to *document a limitation* rather than to pass: Moat is not DLP.

Automated today (CI, GitHub Ubuntu kernel / macOS runner): policy conformance (25 cases), Linux netns enforcement (30
checks), privileged cgroup tests, MoatKit unit tests. Everything below that says **device** must run on Robert's
hardware.

## A. Workflow compatibility (acceptance: M5, 30 consecutive days)

Roll out on the M1 Pro first, then the other laptop and Arch, the mini last. Protect workloads before any
whole-device lockdown.

| Workflow | Exercise | Policy design | Status |
| --- | --- | --- | --- |
| Tailscale + SSH | MagicDNS and IP access, new and existing sessions, direct/relay, reconnect, sleep/wake, exit nodes | Narrow transport/control permissions, named management peers, local recovery proven | device ☐ |
| Plex | Local and remote playback, login, discovery, metadata, updates, transcoding | Own service profile; do not assume LAN-only | device ☐ |
| BlueBubbles | Messaging, attachments, background delivery, reconnect, server reboot | Own profile; Firebase notification dependency means a whole-device block affects it | device ☐ |
| adb to the TV | Real pairing mode (USB / wireless), reconnection, discovery | Learn the real ports; wireless adb uses discovery + paired services, not a fixed 5555 | device ☐ |
| Agent development | Provider login, git fetch/push, package installs, test servers, remote tools, generated executables | Service packs (`packs/services`) + bounded grants; brokered and cloud execution labeled | device ☐ |
| Controller + DNS | Reboot, power/network loss, disk pressure, policy rollback | Endpoint offline operation, bounded spools, documented DNS availability | partly CI (offline restart), device ☐ |
| Streaming (TV) | Auth, ads, CDN rotation, casting | DNS blocklists expanded only after testing | device ☐ |

Keep a running list of observed incompatibilities next to this table.

## B. Adversarial-but-benign suite

Run against a controlled canary destination (an HTTPS endpoint you own that logs every request) and canary data.

| Case | Expected | Linux CI | Device |
| --- | --- | --- | --- |
| Direct IP to a denied destination | Blocked | ✅ netns | ☐ macOS |
| Alternative resolver / DoH from a session | Blocked unless allowed; DNS-only devices: documented bypass | ☐ | ☐ |
| IPv6 path to a denied destination | Blocked | ✅ netns | ☐ macOS |
| UDP / QUIC | Blocked unless allowed | ✅ netns (UDP) | ☐ QUIC both |
| HTTP redirect from an allowed host to a denied host | Second connection blocked | ☐ | ☐ |
| Rapid fork/exec chain, detached grandchild, `setsid` daemon | Inherits session; torn down at session end | ✅ netns + privileged | ➖ macOS (no sessions) |
| PID reuse vs a stale "allow once" | Rejected | ✅ controller tests | ☐ |
| Pre-opened socket passed into a session | Not inherited (CLOEXEC) | ✅ privileged | ➖ |
| cgroup self-escape write | Fails | ✅ privileged + netns | ➖ |
| Shared broker (Docker socket, SSH agent, D-Bus, browser debug port) | Hidden or labeled unresolved | ✅ hiding (privileged) | ☐ |
| Abstract Unix socket broker | **Documented limitation** | ➖ | ☐ |
| Container / VM path | Coverage labeled; no silent claim | ☐ | ☐ |
| Allowed provider used to write data (e.g. GitHub API gist) | **Documented limitation**: allowed | ➖ | ☐ |
| Active stream (WebSocket / QUIC) during a policy change | Measure bytes sent before revocation; no revocation claim on macOS | ☐ | ☐ |
| Filter/daemon crash and restart; upgrade | Coverage reported; no fail-closed claim | ☐ | ☐ |
| Interrupted update, incompatible policy, expired snapshot | Last working revision kept; stale reported | ✅ endpoint tests | ☐ |
| Replayed approval / snapshot | Rejected | ✅ | ☐ |
| Controller outage | Local policy keeps enforcing; isolation stays | ✅ netns offline restart | ☐ |
| Spool full / log gap | Gap visible, enforcement unaffected | ✅ spool tests | ☐ |
| Clean uninstall | No leftover rules/tables/extensions | ☐ | ☐ |

The device-only harness lives in `tests/adversarial/` (see its README). It refuses to run in CI or without an
explicit canary URL, because results from a CI kernel are not evidence about Robert's machines.
