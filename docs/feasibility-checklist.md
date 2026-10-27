# Phase 0 feasibility checklist

> **Historical checklist.** This is phase 0 of the source roadmap ([ROADMAP.md](ROADMAP.md)). Progress is now tracked
> by release gate and work package in the [claim ledger](STATUS.md) (MASTER_ROADMAP §11–§13); this page is kept so
> the phase 0 questions and their answers stay findable. G0 (truthful experimental build) is met; nothing is supported
> on a real device.

Each item is either done in the repository (with CI or unit evidence only), needs a real device, or needs a decision
or an account only Robert can provide.

## 1. Contract, coverage, failure table, policy semantics

- [x] [Protection contract and coverage levels](protection-contract.md)
- [x] [Failure behavior](failure-behavior.md)
- [x] [Policy semantics](policy-semantics.md) + implementation-independent conformance cases (`conformance/cases`)
- [x] [Threat model](threat-model.md), [privacy](privacy.md)
- [x] Versioned contracts with canonical digests and shared fixtures (W01, #13; [contracts/README.md](../contracts/README.md))
- [x] Conservative structured diff and profile capability checks (W02, #16)

## 2. Minimal signed Mac filter on a clean second Mac

- [x] Content-filter system extension, app, typed XPC surface, recovery UI, unsigned CI build (`macos/`)
- [x] Engine hardening in unsigned CI (W07, #19; first canary refused, #62) and the standalone Apps-first app with
      owner-signed local apply (W12, #29, #45)
- [ ] **Robert:** Apple Developer Program membership, Developer ID certificates, Network Extension
      (content-filter-provider-systemextension) Developer ID provisioning profiles for `<prefix>.moat` and
      `<prefix>.moat.filter` ([#2](https://github.com/robzilla1738/moat/issues/2))
- [ ] **Robert:** `macos/scripts/release.sh` → signed, notarized, stapled DMG ([#2](https://github.com/robzilla1738/moat/issues/2))
- [ ] **Device:** clean install on the second Mac; approve extension; enable filter ([#7](https://github.com/robzilla1738/moat/issues/7))
- [ ] **Device:** trusted key file installed; signed snapshot applied; a deny observed blocking; Activity shows it
- [ ] **Device:** reboot / pre-login behavior; sleep/wake; extension upgrade; extension crash (what happens to flows?)
- [ ] **Device:** removal (deactivate → uninstall) leaves nothing behind

## 3. Fast children, delegated helpers, revocation, VPNs; Endpoint Security decision

- [ ] **Device:** rapid exec chains and delegated helpers (XPC services, `launchd` helpers): which app identity does
      the filter see? Record in [platforms/macos.md](platforms/macos.md)
- [ ] **Device:** existing-flow behavior on policy change (no revocation claim on macOS until measured)
- [ ] **Device:** [VPN matrix](vpn-test-matrix.md) rows M1–M12 ([#8](https://github.com/robzilla1738/moat/issues/8))
- [ ] **Robert:** decide whether to request the Endpoint Security entitlement (ancestry,
      [#3](https://github.com/robzilla1738/moat/issues/3)); until then ancestry is "unsupported" on macOS and session
      rules are omitted with a report

## 4. Linux adapter vs OpenSnitch; pre-launch session identity

- [x] OpenSnitch question answered by measurement, not desk review: **OpenSnitch was not adopted**, read-only or
      enforcing (W09, #25, run 40545113846; [decision](decisions/W09-linux-ordinary-apps.md)). The earlier
      [desk assessment](platforms/opensnitch-adapter-feasibility.md) is superseded.
- [x] Native observe-only ordinary-app inventory (W10, #30, #41); ordinary-app **enforcement stays unavailable**
      ([W10 decision](decisions/W10-enforcement.md), [loader decision](decisions/W10-increment-3-loader.md))
- [x] `moat-launch` pre-exec cgroup v2 boundary + nftables, launch authority, session egress proxy and durable
      activation, proven in CI netns (W04–W06) and as a packaged unit on an Ubuntu runner (W11)
- [ ] **Device:** same suite on Robert's Omarchy kernel (`sudo REQUIRE_NFT=1 linux/tests/netns-enforcement.sh`,
      `release/recovery-drill.sh local /usr/bin`; [#6](https://github.com/robzilla1738/moat/issues/6))

## 5. Real sensor events into Digital Kingdom

- [x] Controller → Digital Kingdom incident feed with producer authority enforced before sending
      (`controller/src/dkfeed.ts`, W16, #44; component tests only)
- [ ] **Device:** real events from the M1 Pro / Arch into Robert's Digital Kingdom instance
      ([#10](https://github.com/robzilla1738/moat/issues/10))

## 6. Reuse/licensing and supported matrix

- [x] [Licensing note](licensing.md): Apache-2.0, no GPL code copied; licence report with a copyleft gate (W15)
- [x] [Support matrix](support-matrix.md) page exists; it lists **no supported configurations**
- [ ] **Robert:** declare the supported minimum macOS version and Omarchy kernel line after device runs. Today the
      app's deployment target is macOS 14.0 (`macos/Moat/Config/Moat.xcconfig`, `MoatKit/Package.swift`) while the
      cask template says Ventura or later; reconcile before a release

## Exit gate

A documented real-flow test matrix and an honest coverage UI, with no unsupported claims about full ancestry,
fail-closed behavior or VPN compatibility. The UI side is done and is what G0 checked (everything says *untested* /
*unsupported* until proven; live actions report receipts only, W08). The real-flow matrix needs the device items
above.
