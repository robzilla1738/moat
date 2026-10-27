# Status

Every roadmap item, tracked honestly. Updated with each batch; the commit history is the audit trail.

| Mark | Meaning |
| --- | --- |
| ✅ **done** | Implemented and covered by automated tests in CI. |
| 🔬 **done, needs real-device proof** | Implemented and tested in CI, but the claim depends on Robert's hardware (signed macOS install, Omarchy kernel, his VPNs, his services). The UI keeps saying *untested* until the proof is recorded here. |
| 🔑 **blocked on Robert** | Needs an account, credential, decision, or physical action only Robert can take. |
| ⏭ **later** | Deliberately out of the MVP scope by the roadmap (v1/v2 or excluded). Not started. |

CI workflows: `rust` (fmt, clippy, tests, conformance), `linux-endpoint` (privileged cgroup tests + netns
enforcement on a real kernel), `controller` (TypeScript against the Rust `moatctl`), `web` (typecheck, tests, demo
build, screenshots with overflow/clipping/WCAG AA contrast checks via axe-core, Pages deploy when enabled), `macos`
(MoatKit build + 44 XCTest tests on macOS 26 with Xcode 26; unsigned `xcodebuild` of the app + system extension; real
window screenshots captured in demo mode).

## Product contract and documents

| Item | Status | Where |
| --- | --- | --- |
| Protection contract, three capabilities, coverage levels | ✅ | [protection-contract.md](protection-contract.md) |
| Failure table with per-platform behavior | ✅ | [failure-behavior.md](failure-behavior.md) |
| Policy semantics (precedence, selectors, capabilities, signing) | ✅ | [policy-semantics.md](policy-semantics.md) |
| Threat model | ✅ | [threat-model.md](threat-model.md) |
| Privacy, audit fields, retention | ✅ | [privacy.md](privacy.md) |
| VPN coexistence test matrix (written) | ✅ | [vpn-test-matrix.md](vpn-test-matrix.md) |
| VPN coexistence results | 🔬 none run yet: **no VPN claim** | same |
| Compatibility + adversarial suite (written) | ✅ | [compatibility-suite.md](compatibility-suite.md) |
| Licensing note (Apache-2.0, no GPL code copied) | ✅ | [licensing.md](licensing.md) |
| Phase 0 feasibility checklist | ✅ written; device items open | [feasibility-checklist.md](feasibility-checklist.md) |

## Shared core (`core/`)

| Item | Status | Notes |
| --- | --- | --- |
| Strict declarative policy schema, no scripts, unknown fields rejected | ✅ | `moat-core::policy` |
| Precedence: safety > emergency (deny) > override (allow, expiring, narrow, audited) > explicit (deny beats allow) > profile default; explanation lists overridden rules | ✅ | `eval.rs`, conformance |
| Capability contracts; strict policy fails on missing capability; `skip_with_report` only for allows | ✅ | `compile.rs`, conformance |
| Per-platform compiler (macOS, Linux, Linux IP-only, DNS resolver) | ✅ | 6 compile conformance cases |
| `session_hostname_proxy` capability: session hostname rules compile for TCP; hostname denies must be TCP-only; ordinary hostname rules never use it | ✅ | `compile.rs`, conformance `linux-session-proxy-*` |
| Ed25519 signed snapshots; replay protection; platform check; expiry; rollback as a new revision | ✅ | `signing.rs` |
| Revision states approved → distributed → received → applied → verified | ✅ | `revision.rs`, controller |
| Policy diff and broadening detection | ✅ | `diff.rs` |
| Simulation against recorded observations (estimate, not proof) | ✅ | `simulate.rs`, `moatctl simulate` |
| Process-instance identity and process graph (device, boot, start generation) | ✅ | `identity.rs` |
| Recognizer packs and service packs (data-only, versioned) | ✅ | `packs/` |
| Enrichment: provider / ASN / region facts with source and uncertainty; batch importers | ✅ | `enrichment.rs` |
| Deterministic alert templates; no byte claims without measurement | ✅ | `explain.rs` |
| Producer authority (agents can only assert intent; no self-reported verified blocks) | ✅ | `authority.rs` |
| Implementation-independent conformance suite (31 cases) | ✅ | `conformance/` |
| C ABI for native apps (verify, evaluate, parse) | ✅ | `core/moat-ffi` |
| `moatctl` CLI | ✅ | validate, compile, diff, simulate, keygen, sign, verify, explain, normalize, conformance |

## Linux endpoint (`linux/moatd`)

| Item | Status | Notes |
| --- | --- | --- |
| nftables adapter: verify → render → `nft -c` → one atomic transaction; last working revision kept | 🔬 | CI on GitHub's Ubuntu kernel; Omarchy untested |
| Protected sessions: cgroup v2 placement before exec, broker hiding, uid drop, `no_new_privs`, CLOEXEC, `cgroup.kill` teardown | 🔬 | privileged tests + netns script in CI; Omarchy untested |
| Escape attempts (cgroup move, setuid, preopened sockets, detached children) | 🔬 | CI |
| IPv4/IPv6/UDP enforcement within the session boundary | 🔬 | netns script in CI |
| PTY proxy for interactive programs (`moat-launch --pty`, default on a terminal) | 🔬 | netns checks in CI; try with Claude Code / a TUI on Omarchy |
| Capability probe that only downgrades | 🔬 | |
| Sequenced spool with restart and gap records; quota | ✅ | |
| Local recovery: disable / resume / isolate / clear-isolation; sticky isolation | 🔬 | CI; Omarchy untested |
| Offline operation (last valid policy across restart without controller) | 🔬 | CI "offline restart" |
| systemd unit, Arch PKGBUILD | 🔬 | packaging path written; build/install on Omarchy needed |
| Signed Arch package | 🔑 | needs Robert's packaging key |
| Timed trial (canary) rollback on Linux: `apply --trial-secs`, `recover confirm/rollback`, replay mark kept, first revision cannot be a trial, isolation untouched | 🔬 | unit tests + netns CI (broken trial reverts on its own, cannot be replayed; confirmed trial stays); Omarchy untested. Countdown needs `moatd` running |
| OpenSnitch adapter feasibility | ✅ | [evaluated](platforms/opensnitch-adapter-feasibility.md); native `moatd` chosen |
| Session egress proxy: hostname rules for TCP in protected sessions via TLS SNI / HTTP CONNECT / HTTP Host; no TLS interception; connects to the name it resolves; per-session listener fenced by nftables | 🔬 | unit + in-process tests, netns CI with a TLS lab (allowed/denied SNI, spoofed SNI, CONNECT, Host 403, bare IP, port fence); advertised `untested` until run on Omarchy. UDP stays IP-only; domain fronting remains possible |

## macOS endpoint (`macos/`)

| Item | Status | Notes |
| --- | --- | --- |
| SwiftUI app redesigned in Liquid Glass (macOS 26): NavigationSplitView glass sidebar, glass toolbar, `glassEffect` / `GlassEffectContainer` / `glassEffectID`, `.glass` buttons, `backgroundExtensionEffect` hero, soft scroll edges; macOS 14/15 fallback; Reduce Transparency / Increase Contrast / Reduce Motion | ✅ | builds on `macos-26` + Xcode 26 in CI; `docs/screenshots/macos-*.png` are captured from the real app window on the CI runner in demo mode (unsigned build, demo data). Not yet looked at on a real Mac |
| Menu bar extra: status, recent blocks, isolate with a second explicit confirmation | ✅ | `MenuBarView.swift`; render test + window screenshot (the panel hosted in a window for capture; the live status-item popover is not captured in CI) |
| First-run onboarding: honest coverage labels, extension approval, content filter, signer key (owner adds it with sudo; app only reads) | ✅ UI · 🔑🔬 flow | approval steps need a signed build on a real Mac |
| NEFilterDataProvider system extension (outbound socket flows, audit-token identity, drop before data, reports for bytes) | 🔬 | builds unsigned in CI; never run as a signed extension |
| Typed XPC control surface (7 operations, no trust changes), caller code-signing requirement, refuses all callers when unsigned | 🔬 | logic unit-tested; XPC path needs a signed build |
| Policy store: verified atomic apply, last known good, canary auto-rollback, replay mark kept across rollback | ✅ | MoatKit tests |
| Emergency isolation persisted, survives restart and canary rollback; exit needs typed phrase | 🔬 | unit-tested; device proof needed |
| Event spool with overflow / restart gap markers | ✅ | |
| Rust core via FFI (verify + evaluate) with real signed fixtures | ✅ | MoatCoreBridge tests on macOS runner |
| Session rules omitted on macOS with a report; session profiles refused | ✅ | conformance `macos-omits-session-rules` |
| Recovery UI and uninstall guidance | ✅ | |
| Homebrew cask template + render script | ✅ | `macos/Casks`, `scripts/render-cask.sh` |
| Signing / notarization / stapling script (refuses without Developer ID; checked in CI) | ✅ script · 🔑 run | `scripts/release.sh` |
| Apple Developer Program, Developer ID certs, NE (content-filter-provider-systemextension) provisioning profiles | 🔑 | |
| Signed, notarized release + private Homebrew tap | 🔑 | after the above |
| Clean install on a second Mac; approval; blocking; restart; removal | 🔑🔬 | phase 0 item 2 |
| Reboot / pre-login, sleep/wake, unattended mini, Apple Silicon, IPv6/UDP/QUIC, rapid exec chains, delegated helpers, existing sockets, extension crash/upgrade | 🔬 | none measured yet; **no fail-closed claim** |
| Endpoint Security (process ancestry) | 🔑 decision | ancestry stays *unsupported* until requested and granted |
| Existing-flow revocation | 🔬 | not tested; "block new connections" only |
| macOS protected sessions | ⏭ | excluded as decided; no tested macOS boundary |

## Controller and fleet (`controller/`, `web/`)

| Item | Status | Notes |
| --- | --- | --- |
| Enrollment with device keys; mutually authenticated, signed, replay-protected sync | ✅ | |
| Policy service with a separate signer identity/process; owner key required for broadening | ✅ | |
| Temporary grant overlay; "Allow once for this session" bound to incident, revision, session instance, owner; stale rejected | ✅ | |
| Flow store (separate SQLite) with 30/90-day retention and quota | ✅ | |
| Attention queue: grouped incidents with counts; coverage loss and gaps raised | ✅ | |
| Stale devices shown as degraded, never their last claim | ✅ | |
| ntfy / webhook notifier with opaque references | ✅ | |
| Harness/Dispatch launch contract API (typed; never launches itself) | ✅ | |
| AdGuard Home / Pi-hole DNS-only adapters (phones/TV labeled DNS-only) | 🔬 | needs Robert's resolver + devices |
| Digital Kingdom evidence feed (source authority preserved) | 🔬 | needs Robert's DK instance |
| Reference sync agent for `moatd` | ✅ | end-to-end test over HTTP |
| Phone-first web UI (Home, Activity, Sessions, Rules, Devices, Apps, Coverage), dark/light, demo + live API | ✅ | `docs/screenshots/` |
| Web liquid-glass refresh: glass chrome only (top bar, floating tab bar, sidebar, segmented, decision bar, toasts); solid fallbacks for no `backdrop-filter`, `prefers-reduced-transparency`, `prefers-contrast`; reduced motion; AA contrast | ✅ | CI renders screenshots and fails on horizontal overflow, clipped text or axe-core contrast violations (20 route checks) |
| Trial / rollback receipts per device; rollback raises attention | ✅ | controller migration 2, test |
| Public demo on GitHub Pages | 🔑 | enable Settings → Pages → Source: GitHub Actions; the workflow then deploys (it skips with a notice until then) |
| Optional APNs path via ntfy upstream | 🔑 decision | disclosed optional cloud dependency |

## Milestones and gates

| Milestone | Status |
| --- | --- |
| Phase 0 contract documents | ✅ |
| Phase 0 signed Mac filter on a clean second Mac | 🔑🔬 |
| Phase 0 child processes / helpers / VPN combinations; Endpoint Security decision | 🔬 / 🔑 |
| Phase 0 Linux pre-launch session path | ✅ CI · 🔬 Omarchy |
| Phase 0 real events into Digital Kingdom | 🔬 |
| Phase 0 licensing + supported matrix | ✅ licensing · 🔑 matrix declaration |
| M1 local Mac experience + private tap | ✅ app (Liquid Glass, menu bar, onboarding) · 🔑 signed release |
| M2 private fleet policy (two Macs, signed snapshots, receipts, staged rollback) | ✅ software · 🔬 two real Macs |
| M3 selected agent sessions (launch integration, one tested boundary, service packs, bounded grants) | ✅ Linux boundary + API · 🔬 Harness/Dispatch wiring on device |
| M4 cross-device proof (Arch adapter, two-platform conformance, DNS, phone web UI) | ✅ software · 🔬 devices |
| M5 thirty days of real workflows | 🔬 |
| Release gate (bypass cases on the declared matrix, offline controller keeps isolation, gaps visible, grants expire, stale approvals rejected, revision state matches endpoints) | ✅ in CI where automatable · 🔬 declared matrix |
| Adversarial harness | ✅ written (`tests/adversarial/`, refuses CI) · 🔬 run |

## Not built, and why

Everything buildable in the plan is built. What remains is either excluded by the roadmap (below), needs Robert's
hardware, credentials or decisions (🔑 / 🔬 above), or was deliberately decided against:

* **macOS protected sessions** — excluded as decided; no tested macOS boundary exists, so session rules are omitted
  on macOS with a report.
* **Hostname rules for ordinary (non-session) traffic on Linux** — nftables cannot attribute ordinary apps and the
  proxy is scoped to sessions on purpose; such rules are rejected or (allows that opt in) left out with a report.

## Excluded from MVP by the roadmap (⏭)

Windows, a custom DNS server, native iOS firewall, universal TLS inspection, automatic trust promotion, remote
autonomous remediation, public community feed, enterprise SSO, hosted service. v1/v2 workstreams (Windows WFP agent,
mobile gateway, team governance, credential/API brokers, remote execution sensors, community intelligence, advanced
mobile) are not started.

## Actions only Robert can take

1. **GitHub Pages:** Settings → Pages → Source: GitHub Actions (then re-run the `web` workflow).
2. **Apple:** Developer Program membership; Developer ID Application certificate; Developer ID provisioning profiles
   for `<prefix>.moat` and `<prefix>.moat.filter` with `content-filter-provider-systemextension`; a `notarytool`
   keychain profile. Then `macos/scripts/release.sh`.
3. **Decide** whether to request the Endpoint Security entitlement.
4. **Install and approve** on the M1 Pro / a second Mac (the first-run onboarding walks through it); put the signer
   public key in `/Library/Application Support/Moat/trusted-keys`; check the Liquid Glass UI, menu bar extra and
   accessibility settings on macOS 26.
5. **Omarchy:** build the package, run `sudo REQUIRE_NFT=1 linux/tests/netns-enforcement.sh target/debug` (now 50
   checks, including trial rollback and the session egress proxy), then try a real `moat-launch --profile
   coding-session -- claude` through the proxy and a `moatd apply --trial-secs 600`; report.
6. **Run** the [VPN matrix](vpn-test-matrix.md), the [adversarial harness](../tests/adversarial/README.md), and the
   30-day workflow suite; record results here.
7. **Optional:** AdGuard Home / Pi-hole on the mini, a Digital Kingdom source key, an ntfy topic.
