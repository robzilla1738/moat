# Status: claim ledger

Moat is an **experimental build**. Release gate G0 ("truthful experimental build", MASTER_ROADMAP §13) is **not yet
met**: the open defects below include packaged systemd restrictions that break launched coding workloads. Until they are closed, treat every protection below as
unproven outside the environment named next to it.

The machine-readable source is [`claim-ledger.json`](claim-ledger.json). A test
(`core/moat-core/tests/claim_ledger.rs`) fails CI if a claim is marked supported without installed or
real-workflow evidence, if a claim cites a defect that does not exist, or if this page leaves a claim out.

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
| `linux.session.hostname-proxy` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40537109945 @ 48f8ee5 | Authorize-before-DNS; streams end at expiry (1.15 s), deny (0.80 s), task close, isolation, daemon stop ([contract](proxy-stream-contract.md)); not the installed unit; domain fronting possible; UDP IP-only. |
| `linux.activation.trial-rollback` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40539984069 @ d0b7336 | Durable journal, fault injection at every step, real disk-full episode in CI netns ([contract](linux-activation-journal.md)); not the installed unit. |
| `linux.spool.gaps` | implemented_unproven | component | unit | pass, rust 40493342610 @ d5270bd | No W01 event envelope yet. |
| `linux.ordinary-apps.inventory` | unsupported_rejected | none | unit | not_run | Not implemented; W09/W10. |
| `linux.ordinary-apps.app-rules` | unsupported_rejected | semantic | unit | pass (rejection), rust 40493342610 | nftables cannot match executables; rejected at compile. |
| `linux.packaging.systemd` | implemented_unproven | native_ci | ci-ubuntu-installed-unit | pass, linux-endpoint 40540159764 @ a63827b | Packaged unit under systemd on Ubuntu: project and /tmp writable, containment probes fail; **not Omarchy**. Keeps `CAP_SYS_PTRACE` ([decision](decisions/W11-cap-sys-ptrace.md)). |
| `macos.filter.app-rules` | implemented_unproven | component | ci-macos-26 | pass, macos 40493342625 @ d5270bd | Never run signed; `D-MAC-CACHE-TRUST` (Lane B). |
| `fleet.web.live-actions` | unknown_degraded | component | ci-node-22 | **fail** (review of d5270bd) | `D-WEB-DEMO-SUCCESS`, `D-INCIDENT-ROUTING` (Lane B, W08). |
| `vpn.coexistence` | unknown_degraded | none | omarchy-installed | not_run | No VPN claim. |

## Open defects

From the pinned review in MASTER_ROADMAP §2. A defect closes only when its regression test is merged and the claim
above is updated with the run that proves it.

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
| `D-MAC-CACHE-TRUST` | Mac cache, trust reload, first canary, stale status. | W06–W08 (Lane B) | open |
| `D-WEB-DEMO-SUCCESS` | Live web actions reuse demo success behavior. | W08 (Lane B) | open |
| `D-INCIDENT-ROUTING` | A notification reference can open the wrong incident. | W08/W13 (Lane B) | open |

## Work packages (MASTER_ROADMAP §12)

| Package | Owner | State |
| --- | --- | --- |
| W01 contracts and ledger | Lane A | ledger, six versioned schemas, canonical rules, 40 shared fixtures; Rust + JS consumers in CI. Swift/TS app consumers: Lane B |
| W02 semantics and broadening | Lane A | structured conservative diff, differential counterexample search, profile capability checks, collision-free backend ids; native-fixture agreement for the supported subset still partial |
| W03 exact grants (core side) | Lane A | core done: device/process/task scope through serialization, idempotent ledger, effective digest; controller adoption and signer/publication journal are Lane B |
| W04 Linux launch authority | Lane A | done in CI netns (kernel caller identity, own-profile-only nested launch, raw/pre-opened socket refused); installed-unit proof is W11 |
| W05 proxy semantics | Lane A | done in CI netns: authorize-before-DNS, stream registry with measured stopping delays, direct/proxied agreement; installed-unit proof is W11 |
| W06 durable activation (Linux) | Lane A | done in CI netns: journal, fault injection at each persistence/backend step, retained rollback intent, independent replay high-water, stop-not-adopt restart; installed-unit proof is W11 |
| W07 Mac engine | Lane B | see Lane B |
| W08 truthful UI | Lane B | see Lane B |
| W09 ordinary-app Linux experiment | Lane A | done: measured in CI (run 40545113846); decision: native inventory, OpenSnitch not adopted, enforcement deferred ([decision](decisions/W09-linux-ordinary-apps.md)) |
| W10 ordinary-app Linux inventory | Lane A | not started |
| W11 installed-platform proofs | Lane A (Linux) / Robert | Linux: packaged unit proven under systemd on an Ubuntu runner (installed-unit.sh); Omarchy run and the `CAP_SYS_PTRACE` decision need Robert. Mac: Lane B |

## Needs Robert

1. **Omarchy:** install the package and run `sudo REQUIRE_NFT=1 linux/tests/netns-enforcement.sh target/debug`
   and a real `moat-launch --profile coding-session -- claude`; results become `omarchy-installed` evidence.
2. **Apple:** Developer Program, Developer ID certificates, NE provisioning profiles, notarytool profile
   (Lane B owns the release path).
3. **`CAP_SYS_PTRACE` in moatd.service:** keep it, or schedule passing the caller's mount namespace over the
   control socket so it can be dropped ([decision page](decisions/W11-cap-sys-ptrace.md)).
4. **Decisions:** grant lifetime defaults and recovery semantics (W01 uses conservative defaults until decided);
   whether to request the Endpoint Security entitlement.
5. **VPN matrix and adversarial harness** on real devices; results are recorded here with dates and versions.
6. **GitHub Pages:** Settings → Pages → Source: GitHub Actions, if the public demo is wanted.

Excluded from this phase by the roadmap: Windows, a custom DNS server, a native iOS firewall, universal TLS
inspection, automatic trust promotion, a hosted service.
