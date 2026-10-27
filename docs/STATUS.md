# Status: claim ledger

Moat is an **experimental build**. Release gate G0 ("truthful experimental build", MASTER_ROADMAP §13) is **not yet
met**: the open defects below include grant scope loss, a launcher path a contained caller can use to broaden itself,
and activation state that is not durably journaled. Until they are closed, treat every protection below as
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
| `core.policy.precedence` | implemented_unproven | semantic | unit | pass, rust 40493342610 @ d5270bd | First-match profile order: `D-PROFILE-ORDER`. |
| `core.diff.broadening` | unknown_degraded | semantic | unit | tests pass, known misses | `D-DIFF-REORDER`, `D-DIFF-SHORTENED-DENY`, `D-DIFF-UNKNOWN-FIELDS`; the signer's owner-key gate inherits them. |
| `core.compile.capability-gate` | implemented_unproven | semantic | unit | pass, rust 40493342610 @ d5270bd | Profiles not capability-checked: `D-PROFILE-CAPABILITY`. |
| `core.signing.snapshot` | implemented_unproven | semantic | unit | pass, rust 40493342610 @ d5270bd | Digest not canonical, excludes overlays: `D-DIGEST-CANONICAL`. |
| `core.grant.scope` | unsupported_rejected | component | ci-node-22 | **fail** (review of d5270bd) | `D-GRANT-SCOPE-LOSS`, `D-GRANT-IDEMPOTENCY`. |
| `linux.session.direct-egress` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40493342431 @ d5270bd | Script-run as root, not the installed unit; `D-LAUNCH-AUTHORITY`, `D-SYSTEMD-WORKSPACE`. |
| `linux.session.launch-authority` | unsupported_rejected | component | ci-ubuntu-26.04-x86_64 | **fail** (review of d5270bd) | `D-LAUNCH-AUTHORITY`. |
| `linux.session.hostname-proxy` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40493342431 @ d5270bd | Admission-only; `D-PROXY-DNS-BEFORE-AUTH`, `D-PROXY-STREAM-LIFETIME`; domain fronting possible; UDP IP-only. |
| `linux.activation.trial-rollback` | implemented_unproven | native_ci | ci-ubuntu-26.04-x86_64 | pass, linux-endpoint 40493342431 @ d5270bd | Not journaled or fault-injected: `D-ACTIVATION-JOURNAL`. |
| `linux.spool.gaps` | implemented_unproven | component | unit | pass, rust 40493342610 @ d5270bd | No W01 event envelope yet. |
| `linux.ordinary-apps.inventory` | unsupported_rejected | none | unit | not_run | Not implemented; W09/W10. |
| `linux.ordinary-apps.app-rules` | unsupported_rejected | semantic | unit | pass (rejection), rust 40493342610 | nftables cannot match executables; rejected at compile. |
| `linux.packaging.systemd` | unknown_degraded | none | omarchy-installed | not_run | `D-SYSTEMD-WORKSPACE`. |
| `macos.filter.app-rules` | implemented_unproven | component | ci-macos-26 | pass, macos 40493342625 @ d5270bd | Never run signed; `D-MAC-CACHE-TRUST` (Lane B). |
| `fleet.web.live-actions` | unknown_degraded | component | ci-node-22 | **fail** (review of d5270bd) | `D-WEB-DEMO-SUCCESS`, `D-INCIDENT-ROUTING` (Lane B, W08). |
| `vpn.coexistence` | unknown_degraded | none | omarchy-installed | not_run | No VPN claim. |

## Open defects

From the pinned review in MASTER_ROADMAP §2. A defect closes only when its regression test is merged and the claim
above is updated with the run that proves it.

| Defect | Summary | Package | Status |
| --- | --- | --- | --- |
| `D-PROFILE-ORDER` | Profile selection is implicit first match; overlapping profiles accepted. | W02 | open |
| `D-DIFF-REORDER` | Reordering overlapping profiles is not classified as broadening. | W02 | open |
| `D-DIFF-SHORTENED-DENY` | Shortening a deny's expiry is classified as narrowing. | W02 | open |
| `D-DIFF-UNKNOWN-FIELDS` | Changes to fields the diff does not inspect are not broadening. | W02 | open |
| `D-PROFILE-CAPABILITY` | Unsupported restrictive profiles compile and silently fall back. | W02 | open |
| `D-DIGEST-CANONICAL` | Digests are not canonical; effective digest excludes overlays. | W01/W03 | open |
| `D-GRANT-SCOPE-LOSS` | Generated grants lose device and process-generation scope. | W03 | open |
| `D-GRANT-IDEMPOTENCY` | A retried grant request mints a fresh expiry. | W03 | open |
| `D-LAUNCH-AUTHORITY` | A contained caller can request a looser session through the control socket. | W04 | open |
| `D-PROXY-DNS-BEFORE-AUTH` | A denied hostname can be resolved before authorization. | W05 | open |
| `D-PROXY-STREAM-LIFETIME` | No stream registry; admission vs stream expiry undefined. | W05 | open |
| `D-ACTIVATION-JOURNAL` | Apply/rollback state not journaled or fault-tested. | W06 | open |
| `D-SYSTEMD-WORKSPACE` | Packaged systemd restrictions break launched coding workloads. | W11 | open |
| `D-MAC-CACHE-TRUST` | Mac cache, trust reload, first canary, stale status. | W06–W08 (Lane B) | open |
| `D-WEB-DEMO-SUCCESS` | Live web actions reuse demo success behavior. | W08 (Lane B) | open |
| `D-INCIDENT-ROUTING` | A notification reference can open the wrong incident. | W08/W13 (Lane B) | open |

## Work packages (MASTER_ROADMAP §12)

| Package | Owner | State |
| --- | --- | --- |
| W01 contracts and ledger | Lane A | ledger, six versioned schemas, canonical rules, 38 shared fixtures; Rust + JS consumers in CI. Swift/TS app consumers: Lane B |
| W02 semantics and broadening | Lane A | not started |
| W03 exact grants (core side) | Lane A | not started |
| W04 Linux launch authority | Lane A | not started |
| W05 proxy semantics | Lane A | not started |
| W06 durable activation (Linux) | Lane A | not started |
| W07 Mac engine | Lane B | see Lane B |
| W08 truthful UI | Lane B | see Lane B |
| W09 ordinary-app Linux experiment | Lane A | not started |
| W10 ordinary-app Linux inventory | Lane A | not started |
| W11 installed-platform proofs | Lane A (Linux) / Robert | not started |

## Needs Robert

1. **Omarchy:** install the package and run `sudo REQUIRE_NFT=1 linux/tests/netns-enforcement.sh target/debug`
   and a real `moat-launch --profile coding-session -- claude`; results become `omarchy-installed` evidence.
2. **Apple:** Developer Program, Developer ID certificates, NE provisioning profiles, notarytool profile
   (Lane B owns the release path).
3. **Decisions:** grant lifetime defaults and recovery semantics (W01 uses conservative defaults until decided);
   whether to request the Endpoint Security entitlement.
4. **VPN matrix and adversarial harness** on real devices; results are recorded here with dates and versions.
5. **GitHub Pages:** Settings → Pages → Source: GitHub Actions, if the public demo is wanted.

Excluded from this phase by the roadmap: Windows, a custom DNS server, a native iOS firewall, universal TLS
inspection, automatic trust promotion, a hosted service.
