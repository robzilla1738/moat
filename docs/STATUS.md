# Status: claim ledger

Moat is an **experimental build**. Nothing is supported on real devices: no claim below is `supported_installed`,
and no claim has installed evidence on Robert's machines. Every result comes from GitHub CI runners or unit tests,
in the environment named next to it.

## Where Moat stands, by gate (MASTER_ROADMAP §11.1, §13)

| Gate | Status | What blocks it |
| --- | --- | --- |
| **G0** truthful experimental build | **Met** (2026-10-27). Every defect from the baseline review is closed with a merged regression test and a cited CI run; no claim records a fail. Live UI success cannot be simulated, grants keep their scope, a contained caller cannot broaden itself through Moat, and a persistence failure is never reported as durable activation (§13 stop conditions). | Nothing for G0. This is a truthful *experimental* build: it says what is unproven, and nothing is supported on real devices. |
| **G1** useful local Mac alpha | **Not started on a device.** The standalone Mac journey runs in CI unsigned and has never run as a signed, approved system extension. | Apple Developer ID, Network Extension provisioning profiles and notarization ([#2](https://github.com/robzilla1738/moat/issues/2)); a clean signed install on a second Mac ([#7](https://github.com/robzilla1738/moat/issues/7)); `D-MAC-CACHE-TRUST`. Linux installed proof on Omarchy ([#6](https://github.com/robzilla1738/moat/issues/6)) moves alongside it. |
| **G2** cross-platform local beta | **Blocked.** | Linux ordinary-app enforcement is unavailable: no hook is proven ([W10 decision](decisions/W10-enforcement.md)); the BPF loader is chosen ([increment 3](decisions/W10-increment-3-loader.md)) but the BPF program licence needs Robert's decision. Ordinary-app inventory is observe-only and CI-only. G1 is required first. |
| **G3** private fleet beta | **Blocked.** Fleet sync, staged rollout, learning and DNS adapters pass component tests in CI only. | A real Mac companion (G1), two real endpoints through a 24-hour controller outage, reboot, key rotation and stale approvals, and phone approvals on a device. |
| G4 / G5 | Not started. | Compatibility suite and 30 days of real workflows ([#11](https://github.com/robzilla1738/moat/issues/11)), VPN matrix ([#8](https://github.com/robzilla1738/moat/issues/8)), independent review. |

Decision records: [W09 ordinary apps on Linux](decisions/W09-linux-ordinary-apps.md) ·
[W10 enforcement stays unavailable](decisions/W10-enforcement.md) ·
[W10 BPF loader](decisions/W10-increment-3-loader.md) ·
[W11 `CAP_SYS_PTRACE`](decisions/W11-cap-sys-ptrace.md) · [naming](naming.md).
Support: [support matrix](support-matrix.md) (no supported configurations yet) ·
[recovery and update policy](recovery-update-policy.md) · [recovery drill](recovery-drill.md) ·
[security reporting](../SECURITY.md).

Release artifacts: each build of the `release` workflow produces the release manifest (generated from this ledger),
CycloneDX SBOMs, the licence report and `SHA256SUMS`. Builds from main and `v*` tags also get a keyless Sigstore
signature over `SHA256SUMS` and a GitHub build-provenance attestation for every asset. These say which workflow
built which bytes from which commit. They are not policy authority: the owner policy key is a separate trust domain,
never present in CI, and not used to sign releases. No Apple Developer ID signature, notarization or signed Arch
package exists yet.

The machine-readable source is [`claim-ledger.json`](claim-ledger.json). A test
(`core/moat-core/tests/claim_ledger.rs`) fails CI if a claim is marked supported without installed or
real-workflow evidence, if a claim cites a defect that does not exist, or if this page leaves a claim out.

Supported platforms and end-of-support rules: [support-matrix.md](support-matrix.md). Per-build test coverage:
the release manifest (an asset of every release, and an artifact of the `release` and `release-engineering`
workflows).

## How to read a claim

| Field | Meaning |
| --- | --- |
| Claim | The smallest testable capability cell (backend + mode + subject + destination evidence + transport + lifecycle + environment). |
| Disposition | `supported_installed` · `implemented_unproven` · `unsupported_rejected` · `omitted_accepted` · `unknown_degraded` (MASTER_ROADMAP §5.2). |
| Evidence | `semantic` (pure functions) · `component` (real protocol boundary) · `native_ci` (real OS hooks on a CI runner) · `installed` (the shipped package/extension) · `real_workflow` (Robert's devices and daily use). |
| Environment | Where the last result came from (see below). |
| Last result | What the test actually reported, with the CI run. `not_run` is not a pass. |

**Nothing is `supported_installed` today**: no claim has installed or real-workflow evidence yet.

## Environments

| ID | What it is |
| --- | --- |
| `ci-ubuntu-26.04-x86_64` | GitHub runner ubuntu-26.04, kernel 7.0.0-1017-azure, cgroup2fs, nftables 1.1.6; tests run as root in a netns lab. Not the installed package or the systemd unit. |
| `ci-macos-26` | GitHub macos-26 runner, Xcode 26, unsigned builds, no activated system extension. |
| `ci-node-22` | GitHub ubuntu runner, Node 22, controller tests against the Rust `moatctl`. |
| `ci-release` | GitHub ubuntu runner in the `release` workflow; Sigstore public-good signing with the workflow's OIDC identity and GitHub's attestation store. |
| `unit` | `cargo test`, no OS hooks. |
| `omarchy-installed` | Robert's Omarchy machine with the packaged service. No result recorded. |
| `mac-signed-installed` | Signed, notarized install on a real Mac. No result recorded. |

## Claims

| Claim | Disposition | Evidence | Environment | Last result | Limits / open defects |
| --- | --- | --- | --- | --- | --- |
| `core.policy.schema-strict` | implemented_unproven | semantic | unit | pass, rust 40493342610 @ d5270bd | Semantics only. |
| `core.policy.precedence` | implemented_unproven | semantic | unit | pass, rust 40493342610 @ d5270bd | First-match profile order documented; reorders classified as broadening. |
| `core.diff.broadening` | implemented_unproven | semantic | unit | pass (local, W02) | Conservative structured diff + differential counterexample search; signer should parse structured `changes`. |
| `core.compile.capability-gate` | implemented_unproven | semantic | unit | pass (local, W02) | Profiles capability-checked; Linux backend id collisions rejected. |
| `core.signing.snapshot` | implemented_unproven | semantic | unit | pass, rust 40493342610 @ d5270bd | Canonical policy digest; effective digest binds overlays. |
| `core.grant.scope` | implemented_unproven | semantic | unit | pass (W03 core + controller/signer CI) | Controller plans `moat.grant.v1`, signer compiles with `moatctl compile --grants` and decides from `diff.changes[]`; process grants refused; Linux app grants reported not_enforceable. No installed endpoint has applied a grant yet. |
| `linux.session.direct-egress` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40493342431 @ d5270bd | Script-run as root, not the installed unit; `D-SYSTEMD-WORKSPACE`. |
| `linux.session.launch-authority` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40534200207 @ adca7c2 | Kernel-attested callers; contained caller limited to its own profile. Not via the installed unit; external brokers (docker, ssh-agent) outside the claim. |
| `linux.session.hostname-proxy` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40537109945 @ 48f8ee5 | Authorize-before-DNS; streams end at expiry (1.15 s), deny (0.80 s), task close, isolation, daemon stop ([contract](proxy-stream-contract.md)); not the installed unit; a visible CONNECT host vs SNI/Host mismatch is refused, fronting through an encrypted Host behind an allowed SNI remains possible; UDP IP-only. |
| `linux.activation.trial-rollback` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40539984069 @ d0b7336 | Durable journal, fault injection at every step, real disk-full episode in CI netns ([contract](linux-activation-journal.md)); not the installed unit. |
| `linux.spool.gaps` | implemented_unproven | component | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40555180765 @ e02658c | Bounded spool, durable acks, spool_low_seq/local_change outbox; no W01 envelope; no real controller round trip. |
| `linux.ordinary-apps.inventory` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40547438730 @ 3a54a66 | **observe_only** (`moatd inventory`, `moatd run --ordinary-inventory-ms`): counted TCP loss, unknown identity with reason, UDP completeness unmeasured, other netns not observed; not Omarchy. |
| `linux.ordinary-apps.connect-attribution` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40559834509 @ f64a4ad | **observe_only** (`moatd inventory --ebpf`, bpftrace 0.25 on `sock:inet_sock_set_state`): 20/20 short-lived connects attributed, 20,000-connect flood fully accounted vs kernel ActiveOpens; forced buffer loss did not occur on the runner (loss path unit-tested only); TCP only; daemon path unchecked; not Omarchy. |
| `linux.ordinary-apps.app-rules` | unsupported_rejected | semantic | unit | pass (rejection), rust 40493342610 | nftables cannot match executables; rejected at compile. |
| `linux.packaging.systemd` | implemented_unproven | native_ci | ci-ubuntu-installed-unit | pass, linux-endpoint 40540159764 @ a63827b | Packaged unit under systemd on Ubuntu: project and /tmp writable, containment probes fail; **not Omarchy**. Keeps `CAP_SYS_PTRACE` ([decision](decisions/W11-cap-sys-ptrace.md)). |
| `macos.filter.app-rules` | implemented_unproven | component | ci-macos-26 | pass, macos 40577981264 @ 2ad8be5 | Never run signed. Generation-bound cache, verified restoration, trust reload, first-canary refusal and stale XPC are unit-tested only. |
| `fleet.web.live-actions` | implemented_unproven | component | ci-node-22 | pass, web 40577605299 @ 08e315e | Authenticated actions bound to incident and policy revision, pending until an endpoint receipt; exact notification references. Chromium against a real controller in CI; no phone, no real endpoint. |
| `fleet.sync.acks-reconcile` | implemented_unproven | component | ci-node-22 | pass, controller 40565815980 @ 7b31e81 | Contiguous acks with declared gaps, receipt-based reconciliation, staged rollout, offline local changes held for the owner; against moatd's sync-state and spool files, not two real endpoints; no 24-hour outage (G3). |
| `learning.reviewed-baselines` | implemented_unproven | component | ci-node-22 | pass, controller 40565815980 @ 7b31e81 | Bounded identity-bound capture, immutable reviewed baselines, drift as new candidates, three packs; no capture from a real device, alert volume unmeasured. |
| `dns.adapters.adguard-pihole` | implemented_unproven | component | ci-node-22 | pass, controller 40565815980 @ 7b31e81 | AdGuard Home and Pi-hole v6 against recorded responses and mocks, not a live instance; DNS-only coverage (#9, #10). |
| `release.integrity` | implemented_unproven | component | ci-release | pass, release 40569608036 @ ae2fe41 | SHA256SUMS, CycloneDX SBOMs with a coverage gate, keyless Sigstore signature and per-asset build-provenance attestations, tamper negative controls. Not policy authority; the owner policy key is separate and unused. No Developer ID, notarization or signed Arch package. |
| `linux.recovery.local-drill` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, release 40569608036 @ ae2fe41 | [Recovery drill](recovery-drill.md) with real moatd in a CI netns: isolation across crash and restart, disable with the daemon stopped, trial revert and rollback, corrupt journal, newer-schema state, untrusted signer. Not the installed unit on Omarchy; no reboot. |
| `vpn.coexistence` | unknown_degraded | none | omarchy-installed | not_run | No VPN claim. |

## Defects

From the pinned review in MASTER_ROADMAP §2. A defect closes only when its regression test is merged and the claim
above is updated with the run that proves it. **All defects are closed.**

| Defect | Summary | Package | Status |
| --- | --- | --- | --- |
| `D-PROFILE-ORDER` | Profile selection is implicit first match; overlapping profiles accepted. | W02 | **closed** (W02) |
| `D-DIFF-REORDER` | Reordering overlapping profiles is not classified as broadening. | W02 | **closed** (W02) |
| `D-DIFF-SHORTENED-DENY` | Shortening a deny's expiry is classified as narrowing. | W02 | **closed** (W02) |
| `D-DIFF-UNKNOWN-FIELDS` | Changes to fields the diff does not inspect are not broadening. | W02 | **closed** (W02) |
| `D-PROFILE-CAPABILITY` | Unsupported restrictive profiles compile and silently fall back. | W02 | **closed** (W02) |
| `D-DIGEST-CANONICAL` | Digests are not canonical; effective digest excludes overlays. | W01/W03 | **closed** (W03 core) |
| `D-GRANT-SCOPE-LOSS` | Generated grants lose device and process-generation scope. Core and controller fixed (`moatctl compile --grants`, no controller-rendered rules). | W03 | closed (controller/test/grants.test.ts) |
| `D-GRANT-IDEMPOTENCY` | A retried grant request mints a fresh expiry. Controller follows `GrantLedger` semantics (same key + same request = original grant; different request = 409). | W03 | closed (controller/test/grants.test.ts) |
| `D-LAUNCH-AUTHORITY` | A contained caller can request a looser session through the control socket. | W04 | **closed** (W04, netns run 40534200207) |
| `D-PROXY-DNS-BEFORE-AUTH` | A denied hostname can be resolved before authorization. | W05 | **closed** (W05, netns run 40537109945) |
| `D-PROXY-STREAM-LIFETIME` | No stream registry; admission vs stream expiry undefined. | W05 | **closed** (W05, netns run 40537109945) |
| `D-DEVICE-SCOPE-FLEET` | Device-scoped rules refused for the whole fleet (issue #26). | W02 | **closed** (device-targeted compiles) |
| `D-ACTIVATION-JOURNAL` | Apply/rollback state not journaled or fault-tested. | W06 | **closed** (W06, netns run 40539984069) |
| `D-SYSTEMD-WORKSPACE` | Packaged systemd restrictions break launched coding workloads. | W11 | **closed** (W11, installed-unit job in linux-endpoint 40540159764) |
| `D-MAC-CACHE-TRUST` | Mac cache, trust reload, first canary, stale status. | W06–W08 (Lane B) | **closed** (W07 #19; first canary #62; macos 40577981264) |
| `D-WEB-DEMO-SUCCESS` | Live web actions reuse demo success behavior. | W08 (Lane B) | **closed** (W08 #14; web 40577605299 live e2e) |
| `D-INCIDENT-ROUTING` | A notification reference can open the wrong incident. | W08/W13 (Lane B) | **closed** (W08 #14; controller 40577605234, web 40577605299) |

## Work packages (MASTER_ROADMAP §12)

| Package | Owner | State |
| --- | --- | --- |
| W01 contracts and ledger | Lane A | ledger, six versioned schemas, canonical rules, 40 shared fixtures; Rust + JS consumers in CI. Swift/TS app consumers: Lane B |
| W02 semantics and broadening | Lane A | structured conservative diff, differential counterexample search, profile capability checks, collision-free backend ids; native-fixture agreement for the supported subset still partial |
| W03 exact grants (core side) | Lane A | core done: device/process/task scope through serialization, idempotent ledger, effective digest; controller adoption and signer/publication journal are Lane B |
| W04 Linux launch authority | Lane A | done in CI netns (kernel caller identity, own-profile-only nested launch, raw/pre-opened socket refused); installed-unit proof is W11 |
| W05 proxy semantics | Lane A | done in CI netns: authorize-before-DNS, stream registry with measured stopping delays, direct/proxied agreement; installed-unit proof is W11 |
| W06 durable activation (Linux) | Lane A | done in CI netns: journal, fault injection at each persistence/backend step, retained rollback intent, independent replay high-water, stop-not-adopt restart; installed-unit proof is W11 |
| W07 Mac engine | Lane B | done in macOS CI (unsigned): generation-bound evaluator, expiry-aware cache, candidate validation, verified restoration, trust reload, separate app/process identity, bounded XPC, first canary refused; never run as a signed extension (W11 Mac, Developer ID) |
| W08 truthful UI | Lane B | done: explicit demo/live, evidence-only action states, exact notification references, consumer-computed freshness, hostile identifiers inert; Chromium against the real controller in CI; native UI uses the same stale semantics (StaleTests) |
| W09 ordinary-app Linux experiment | Lane A | done: measured in CI (run 40545113846); decision: native inventory, OpenSnitch not adopted, enforcement deferred ([decision](decisions/W09-linux-ordinary-apps.md)) |
| W10 ordinary-app Linux inventory | Lane A | increments 1–2 done in CI netns, **observe-only**: socket-table inventory and bpftrace connect-time attribution against an independent receiver, loss reported. Increment 3 decided the loader (aya + a separate BPF program, [decision](decisions/W10-increment-3-loader.md)); the program's licence needs Robert ([#53](https://github.com/robzilla1738/moat/issues/53)). Enforcement stays unavailable ([decision](decisions/W10-enforcement.md)) |
| W11 installed-platform proofs | Lane A (Linux) / Robert | Linux: packaged unit passes under systemd on an Ubuntu runner (installed-unit.sh); the Omarchy run ([#6](https://github.com/robzilla1738/moat/issues/6)) and the `CAP_SYS_PTRACE` decision ([#54](https://github.com/robzilla1738/moat/issues/54)) need Robert. Mac: Lane B, blocked on Developer ID ([#2](https://github.com/robzilla1738/moat/issues/2)) |
| W12 standalone local experience | Lane B (Lane A: moat-ffi compile) | Apps-first standalone app, app detail, What changed?, diagnostics in controller, web and macOS; Mac standalone apply compiles with moat-core and the owner key signs the exact snapshot. CI only, unsigned; never run on a real Mac |
| W13 fleet sync | Lane B (Lane A: moatd outbox) | contiguous acks and declared gaps, reconciliation, staged rollout, offline local changes held for the owner, moatd outbox agent; component tests (`fleet.sync.acks-reconcile`, `linux.spool.gaps`) |
| W14 learning | Lane B | bounded capture, reviewed immutable baselines, drift as new candidates, three packs; component tests (`learning.reviewed-baselines`) |
| W15 release | Lane A | SECURITY.md, CODEOWNERS, licence report with copyleft gate, release manifest from this ledger, actions pinned to SHAs, support matrix, naming note, SBOMs, SHA256SUMS, keyless signing and provenance attestations, [recovery drill](recovery-drill.md). Not done: 30-day pilot, independent review, signed platform packages, updater metadata (TUF evaluation), rulesets ([#51](https://github.com/robzilla1738/moat/issues/51)) |
| W16 DNS and Digital Kingdom | Lane B | AdGuard Home and Pi-hole v6 adapters, DNS-only presentation, Digital Kingdom producer authority; component tests (`dns.adapters.adguard-pihole`); no live instance ([#9](https://github.com/robzilla1738/moat/issues/9), [#10](https://github.com/robzilla1738/moat/issues/10)) |

## Needs Robert

Tracked as issues labelled [`blocked-on-robert`](https://github.com/robzilla1738/moat/issues?q=is%3Aopen+label%3Ablocked-on-robert),
[`decision`](https://github.com/robzilla1738/moat/issues?q=is%3Aopen+label%3Adecision) and
[`needs-device-proof`](https://github.com/robzilla1738/moat/issues?q=is%3Aopen+label%3Aneeds-device-proof).

1. **Apple** ([#2](https://github.com/robzilla1738/moat/issues/2), [#7](https://github.com/robzilla1738/moat/issues/7)): Developer Program, Developer ID certificates, NE provisioning profiles, notarytool profile, then a signed install on a clean second Mac. This is the G1 blocker.
2. **Omarchy** ([#6](https://github.com/robzilla1738/moat/issues/6)): install the package, run `sudo REQUIRE_NFT=1 linux/tests/netns-enforcement.sh target/debug`, `sudo release/recovery-drill.sh local /usr/bin` and a real `moat-launch --profile coding-session -- claude`; results become `omarchy-installed` evidence.
3. **Repository settings** ([#51](https://github.com/robzilla1738/moat/issues/51)): enable private vulnerability reporting; add a `main` ruleset with required checks and code-owner review (verified via the API on 2026-10-27: no rulesets, reporting disabled).
4. **Decisions:** naming ([#52](https://github.com/robzilla1738/moat/issues/52)), BPF program licence ([#53](https://github.com/robzilla1738/moat/issues/53)), `CAP_SYS_PTRACE` vs passing the mount namespace ([#54](https://github.com/robzilla1738/moat/issues/54)), sessions stop rather than being adopted on restart ([#55](https://github.com/robzilla1738/moat/issues/55)), `MOAT_SIGNER_CONTROLLER_GRANTS` default ([#56](https://github.com/robzilla1738/moat/issues/56)), grant lifetimes ([#57](https://github.com/robzilla1738/moat/issues/57)), Endpoint Security entitlement ([#3](https://github.com/robzilla1738/moat/issues/3)), APNs via ntfy ([#4](https://github.com/robzilla1738/moat/issues/4)).
5. **Signed Arch package** ([#5](https://github.com/robzilla1738/moat/issues/5)); **GitHub Pages** for the demo ([#1](https://github.com/robzilla1738/moat/issues/1)).
6. **Real devices:** VPN matrix ([#8](https://github.com/robzilla1738/moat/issues/8)), DNS-only coverage on a live resolver ([#9](https://github.com/robzilla1738/moat/issues/9)), Digital Kingdom feed ([#10](https://github.com/robzilla1738/moat/issues/10)), compatibility suite and 30 days of real workflows ([#11](https://github.com/robzilla1738/moat/issues/11)), and the device-only rows of the [adversarial matrix](adversarial-matrix.md) and [recovery drill](recovery-drill.md).

Excluded from this phase by the roadmap: Windows, a custom DNS server, a native iOS firewall, universal TLS
inspection, automatic trust promotion, a hosted service.
