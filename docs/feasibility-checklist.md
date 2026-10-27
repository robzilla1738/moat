# Phase 0 feasibility checklist

From the roadmap's phase 0 (3–5 weeks planning range). Each item is either done in the repository, needs a real
device, or needs a decision or an account only Robert can provide. [STATUS.md](STATUS.md) is the live tracker.

## 1. Contract, coverage, failure table, policy semantics

- [x] [Protection contract and coverage levels](protection-contract.md)
- [x] [Failure behavior](failure-behavior.md)
- [x] [Policy semantics](policy-semantics.md) + 25 implementation-independent conformance cases
- [x] [Threat model](threat-model.md), [privacy](privacy.md)

## 2. Minimal signed Mac filter on a clean second Mac

- [x] Content-filter system extension, app, typed XPC surface, recovery UI, unsigned CI build (`macos/`)
- [ ] **Robert:** Apple Developer Program membership, Developer ID certificates, Network Extension
      (content-filter-provider-systemextension) Developer ID provisioning profiles for `<prefix>.moat` and
      `<prefix>.moat.filter`
- [ ] **Robert:** `macos/scripts/release.sh` → signed, notarized, stapled DMG
- [ ] **Device:** clean install on the second Mac; approve extension; enable filter
- [ ] **Device:** trusted key file installed; signed snapshot applied; a deny observed blocking; Activity shows it
- [ ] **Device:** reboot / pre-login behavior; sleep/wake; extension upgrade; extension crash (what happens to flows?)
- [ ] **Device:** removal (deactivate → uninstall) leaves nothing behind

## 3. Fast children, delegated helpers, revocation, VPNs; Endpoint Security decision

- [ ] **Device:** rapid exec chains and delegated helpers (XPC services, `launchd` helpers): which app identity does
      the filter see? Record in [platforms/macos.md](platforms/macos.md)
- [ ] **Device:** existing-flow behavior on policy change (no revocation claim until measured)
- [ ] **Device:** [VPN matrix](vpn-test-matrix.md) rows M1–M11
- [ ] **Robert:** decide whether to request the Endpoint Security entitlement (ancestry); until then ancestry is
      "unsupported" on macOS and session rules are omitted with a report

## 4. Linux adapter vs OpenSnitch; pre-launch session identity

- [x] [OpenSnitch adapter feasibility](platforms/opensnitch-adapter-feasibility.md) → native `moatd` chosen
- [x] `moat-launch` pre-exec cgroup v2 boundary + nftables, proven in CI (GitHub Ubuntu kernel)
- [ ] **Device:** same suite on Robert's Omarchy kernel (`sudo REQUIRE_NFT=1 linux/tests/netns-enforcement.sh`)

## 5. Real sensor events into Digital Kingdom

- [x] Controller → Digital Kingdom incident feed with source authority preserved (`controller/src/dkfeed.ts`)
- [ ] **Device:** real events from the M1 Pro / Arch into Robert's Digital Kingdom instance

## 6. Reuse/licensing and supported matrix

- [x] [Licensing note](licensing.md): Apache-2.0, no GPL code copied
- [ ] **Robert:** declare the supported minimum macOS version (design target 13 Ventura) and Omarchy kernel line
      after device runs

## Exit gate

A documented real-flow test matrix and an honest coverage UI, with no unsupported claims about full ancestry,
fail-closed behavior or VPN compatibility. The UI side of this is done (everything says *untested* / *unsupported*
until proven); the real-flow matrix needs the device items above.
