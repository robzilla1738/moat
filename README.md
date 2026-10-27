<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset="brand/moat-mark-dark.svg"><img src="brand/moat-mark-light.svg" alt="Moat mark: a keep inside a moat ring that opens only below the gate" width="76" height="76"></picture>

# Moat

**Understand and control what software can send from your devices,<br>with stronger boundaries for the workloads you choose to protect.**

An open, self-hosted outbound firewall for people whose software increasingly acts on their behalf: coding agents,
MCP servers, package installers, local models, generated programs. One signed policy across your Macs and Linux
machines, enforced locally on each device, coordinated by an optional controller you run yourself.

[Status](docs/STATUS.md) · [Support matrix](docs/support-matrix.md) · [Protection contract](docs/protection-contract.md) · [Policy semantics](docs/policy-semantics.md) · [Threat model](docs/threat-model.md)

</div>

<table>
<tr>
<td colspan="2"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/desktop-home-dark.png"><img src="docs/screenshots/desktop-home-light.png" alt="Moat web dashboard on desktop: apps, coverage, blocked and most-active cards (demo data)"></picture></td>
</tr>
<tr>
<td width="64%"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/macos-apps-dark.png"><img src="docs/screenshots/macos-apps-light.png" alt="Moat for macOS: overview bento with coverage, counters, recent flows and most-blocked apps (demo data)"></picture></td>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/mobile-overview-dark.png"><img src="docs/screenshots/mobile-overview-light.png" alt="Moat on a phone: overview with KPI tiles and decisions (demo data)"></picture></td>
</tr>
<tr>
<td colspan="2" align="center"><sub><b>CI captures on demo data, not real devices.</b> Each image follows your GitHub light or dark theme; both versions of every screen are in <a href="docs/screenshots">docs/screenshots</a> (desktop web: <a href="docs/screenshots/desktop-home-light.png">light</a> · <a href="docs/screenshots/desktop-home-dark.png">dark</a>; Mac: <a href="docs/screenshots/macos-apps-light.png">light</a> · <a href="docs/screenshots/macos-apps-dark.png">dark</a>; phone: <a href="docs/screenshots/mobile-overview-light.png">light</a> · <a href="docs/screenshots/mobile-overview-dark.png">dark</a>).</sub></td>
</tr>
</table>

> **Read this first.** Moat is an **experimental build**. Nothing is supported on real devices: no claim is
> `supported_installed`, and every result so far comes from GitHub CI runners or unit tests. The Linux
> protected-session boundary passes on a CI runner kernel and as a packaged unit on an Ubuntu runner, but has not run
> on Omarchy. The macOS content filter has never run as a signed system extension. There is no fail-closed claim, no
> VPN-compatibility claim and no TLS interception. Phones and the TV get **DNS-only** coverage, labelled as such.

## Where Moat stands

The [claim ledger](docs/STATUS.md) is the source; this is its summary by release gate (MASTER_ROADMAP §13).

| Gate | Status | Blocked on |
| --- | --- | --- |
| **G0** truthful experimental build | **Met** (2026-10-27). Every defect from the baseline review is closed with a merged regression test and a cited CI run. | Nothing for G0; it is a truthful *experimental* build. Nothing is supported on real devices. |
| **G1** useful local Mac alpha | Not started on a device | Developer ID, NE provisioning profiles and notarization ([#2](https://github.com/robzilla1738/moat/issues/2)); a signed install on a clean second Mac ([#7](https://github.com/robzilla1738/moat/issues/7)) |
| **G2** cross-platform local beta | Blocked | G1. Linux ordinary-app enforcement is unavailable ([W10 decision](docs/decisions/W10-enforcement.md)); inventory is observe-only; Omarchy proof ([#6](https://github.com/robzilla1738/moat/issues/6)) |
| **G3** private fleet beta | Blocked | Fleet sync, learning and DNS adapters pass in CI only; needs real endpoints, a 24-hour outage test and phone approvals on a device |

Decision records: [W09](docs/decisions/W09-linux-ordinary-apps.md) · [W10 enforcement](docs/decisions/W10-enforcement.md) ·
[W10 BPF loader](docs/decisions/W10-increment-3-loader.md) · [W11 `CAP_SYS_PTRACE`](docs/decisions/W11-cap-sys-ptrace.md) ·
[naming](docs/naming.md). Support: [support matrix](docs/support-matrix.md) (no supported configurations yet) ·
[recovery drill](docs/recovery-drill.md) · [recovery and update policy](docs/recovery-update-policy.md) ·
[security reporting](SECURITY.md).

**Releases** are prereleases built by the `release` workflow: Linux x86_64 binaries (an archive, not a signed
package), source and web tarballs, CycloneDX SBOMs, a licence report, the release manifest generated from the claim
ledger, and `SHA256SUMS` with a keyless Sigstore signature and per-asset GitHub build-provenance attestations. Verify
them with `release/recovery-drill.sh integrity <dir>`. Those signatures identify the workflow and commit that built the
bytes. They are not policy authority: the owner policy key is separate and is not used for releases. There is no
signed or notarized macOS build yet.

## Three things, never blended

| | What it means | Where |
| --- | --- | --- |
| **Observed** | Moat sees a connection and records it. Nothing is blocked, and the UI says *permitted, not enforced*. | macOS (filter with no signed policy), Linux (ordinary-app inventory, observe-only) |
| **Enforced** | Your signed policy decides; a deny happens at the OS hook before data passes. | macOS per-app (untested on device), Linux device/user-wide |
| **Protected session** | A boundary built **before the workload runs**, inherited by every child, escape-tested. Hostname rules for TCP are enforced by a per-session egress proxy (TLS SNI / HTTP CONNECT / Host, no TLS interception). | Linux `moat-launch` (cgroup v2 + nftables); proxy CI-tested, *untested* on Omarchy |

A launcher that only adds a label is an *instrumented* session, not a protected one, and Moat never calls it one.

## What it looks like

<table>
<tr>
<td width="58%"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/macos-activity-dark.png"><img src="docs/screenshots/macos-activity-light.png" alt="macOS Activity"></picture></td>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/macos-menubar-dark.png"><img src="docs/screenshots/macos-menubar-light.png" alt="macOS menu bar extra"></picture></td>
</tr>
<tr>
<td><sub><b>macOS Activity.</b> Blocked flows say <i>blocked before data was sent</i>; observed flows are never called allowed; bytes appear only when macOS reported them.</sub></td>
<td><sub><b>Menu bar extra.</b> Coverage at a glance, recent blocks, and Isolate this Mac behind a second explicit confirmation. Turning isolation off still needs the typed phrase in Recovery.</sub></td>
</tr>
<tr>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/desktop-overview-dark.png"><img src="docs/screenshots/desktop-overview-light.png" alt="Web overview: flows by verdict, blocked hour by hour, when traffic happens, evidence age"></picture></td>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/mobile-allow-once-dark.png"><img src="docs/screenshots/mobile-allow-once-light.png" alt="Phone: allow once for this session"></picture></td>
</tr>
<tr>
<td><sub><b>Overview.</b> Hourly rollups by verdict, blocked attempts per hour, each device's evidence age against the 10-minute freshness limit, and endpoint receipts for the latest revision. Every chart is drawn from recorded fields; demo charts are tagged <i>Sample data</i>.</sub></td>
<td><sub><b>Phone web UI.</b> "Allow once for this session" is bound to the incident, policy revision and session instance; stale approvals are rejected.</sub></td>
</tr>
<tr>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/desktop-rules-dark.png"><img src="docs/screenshots/desktop-rules-light.png" alt="Fleet rules"></picture></td>
<td><picture><source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/macos-onboarding-dark.png"><img src="docs/screenshots/macos-onboarding-light.png" alt="macOS first-run onboarding: what Moat can claim"></picture></td>
</tr>
<tr>
<td><sub><b>Rules.</b> Every revision shows its diff, who authorized it, per-device delivery state, and what each platform had to leave out.</sub></td>
<td><sub><b>First-run onboarding.</b> Starts with what Moat can and cannot claim on this Mac, then walks through extension approval, the content filter and adding your signer key (you add it; the app only reads it).</sub></td>
</tr>
</table>

**About these images.** They are CI captures on demo data, not real devices. The `macos-*.png` files are captured from
the real Moat app window (`screencapture -l`) on GitHub's `macos-26` runner, built unsigned with Xcode 26 and launched
with `--demo`, so the data comes from the demo client backed by the real `ControlHandler`, not from a running content
filter ([`macos/scripts/capture-screenshots.sh`](macos/scripts/capture-screenshots.sh)). The window height is limited
by the runner's small display. The phone and desktop images are the fleet web UI rendered by Playwright from its demo
build ([`web/scripts/screenshots.mjs`](web/scripts/screenshots.mjs)), which also fails CI on overflow, clipped text or
an AA contrast violation; `live-*.png` come from the browser tests against a real controller on the CI runner. The
design system is in [docs/design.md](docs/design.md). More in [docs/screenshots](docs/screenshots).

## What's in this build

Everything here is implemented and tested on GitHub CI runners or in unit tests, at the level the
[claim ledger](docs/STATUS.md) records. None of it has run on Omarchy or a signed Mac.

* **Policy core (W01–W03).** Versioned contracts with canonical digests and shared fixtures; a conservative
  structured diff (anything it cannot prove narrowing counts as broadening); exact grants that keep their device,
  task or executable, destination and port through serialization, idempotent per request, bound to the base policy
  digest, with delegated (phone) issuers limited by an owner-signed delegation.
  [Temporary grants](docs/temporary-grants.md) · [contracts](contracts/README.md)
* **Linux protected sessions (W04–W06, W11).** `moat-launch` builds the boundary before exec; a contained caller can
  only relaunch its own profile. TCP hostname rules go through a per-session egress proxy that refuses a forbidden
  name before any DNS lookup, checks every resolved address, refuses a visible `CONNECT`/SNI mismatch and ends open
  streams on expiry, revocation, isolation, task end and daemon stop. Activation is journaled step by step, the
  replay high-water mark is independent and never lowered, trial revisions roll back unless confirmed, the first
  revision cannot be a trial, and sessions are stopped (not adopted) on restart. Passes the CI netns suite, the
  packaged unit under systemd on an Ubuntu runner and the recovery drill. [Linux](docs/platforms/linux.md) ·
  [proxy contract](docs/proxy-stream-contract.md) · [activation journal](docs/linux-activation-journal.md)
* **Linux ordinary apps (W09–W10).** Observe-only inventory (socket tables, optional bpftrace connect attribution) with
  counted loss. OpenSnitch was measured and not adopted; app rules stay rejected because no enforcing hook is proven.
  [W09](docs/decisions/W09-linux-ordinary-apps.md) · [W10](docs/decisions/W10-enforcement.md)
* **macOS app and filter (W07, W12, W14).** Apps-first app in Moat's bento design (opaque cards on shared
  tokens, light and dark, no translucency; see [design](docs/design.md)), menu bar extra and honest onboarding. The engine is generation-bound, its cache never
  outlives a timed permission, restored state is re-verified, trust reloads live, and a first canary is refused.
  Standalone rules are compiled by moat-core and signed by the Keychain owner key behind user presence. Unsigned CI
  builds only; never checked by eye or run as a signed extension on a real Mac. [macOS](docs/platforms/macos.md)
* **Truthful UI (W08).** Live and demo are separate; *applied* and *active* come only from endpoint receipts; a
  notification reference opens exactly its incident; floods collapse into one summary per window.
  [UI evidence](docs/ui-evidence.md)
* **Fleet, learning, DNS (W13, W14, W16).** Contiguous acknowledgements with declared gaps, receipt-based
  reconciliation, staged rollout and offline local changes held for the owner; reviewed, immutable learning baselines
  and three workflow packs with review screens in web and macOS; read-only AdGuard Home and Pi-hole v6 adapters with
  DNS-only labelling; a Digital Kingdom feed that enforces producer authority. Component tests only.
  [Fleet sync](docs/fleet-sync.md) · [learning](docs/learning.md) · [integrations](docs/integrations.md)
* **Release engineering (W15).** SBOMs with a coverage gate, licence report with a copyleft gate, SHA256SUMS, keyless
  signing and provenance attestations, a release manifest generated from the ledger, pinned actions, and a recovery
  drill. [Recovery drill](docs/recovery-drill.md) · [support matrix](docs/support-matrix.md)

## Architecture

```
  reviewed policy (Git) ──► policy authority ──► signed per-platform snapshots
          ▲                 (separate signer;            │
          │                  owner key to broaden)       ├──► Mac: content-filter system extension ──► existing network path
   private web UI ◄── controller (Mac mini) ◄── receipts, ├──► Linux: moatd (nftables + cgroup v2)  ──► existing network path
   (phone-first)      flow store, incidents,   events     └──► DNS: AdGuard Home / Pi-hole (phones, TV: DNS-only)
                      notifications
```

Traffic never flows through the controller. Endpoints enforce the last valid signed policy on their own, keep a
sequenced spool, and offer local recovery that works when the controller or the tailnet is down.

| Component | Path | Language |
| --- | --- | --- |
| Policy model, compiler, evaluator, signing, conformance | `core/moat-core`, `conformance/` | Rust |
| CLI: validate, compile, diff, simulate, sign, verify, explain | `core/moatctl` | Rust |
| C ABI for native apps | `core/moat-ffi` | Rust |
| Linux endpoint + protected launcher (`moatd`, `moat-launch`) | `linux/` | Rust |
| macOS app, content-filter system extension, MoatKit | `macos/` | Swift |
| Controller: enrollment, policy service, signer, flow store, incidents, notifier, DNS adapters, DK feed | `controller/` | TypeScript (Node 22) |
| Fleet web UI | `web/` | React + Vite |
| Recognizer and service packs (data only) | `packs/` | JSON |

## Quick start

**Policy tooling** (any OS with Rust):

```sh
cargo build --release -p moatctl
./target/release/moatctl validate conformance/policies/home.toml
./target/release/moatctl compile conformance/policies/home.toml --adapter macos --revision 1 -o snap.json
./target/release/moatctl keygen --out ~/moat-signer.key        # keep it out of agent workspaces
./target/release/moatctl sign snap.json --key ~/moat-signer.key -o signed.json
./target/release/moatctl conformance conformance
```

**Linux / Omarchy**: see [docs/platforms/linux.md](docs/platforms/linux.md).

```sh
cd linux/packaging/arch && makepkg -si
sudo moatd trust ~/moat-signer.key.pub && sudo systemctl enable --now moatd
moat-launch --profile coding-session -- claude    # PTY proxy keeps your TUI interactive
```

**macOS**: see [docs/platforms/macos.md](docs/platforms/macos.md). Contributors can build unsigned; a runnable
system extension needs a Developer ID build (`macos/scripts/release.sh`). Run the app with `--demo` to explore.

**Controller + web UI** (on the mini):

```sh
npm ci && cargo build -p moatctl
node controller/src/main.ts init ~/moat-data     # prints the next steps (owner key, signer service, serve)
npm run dev -w web                               # or the static demo: npm run build:demo -w web
```

## Design rules (and where they do not hold yet)

These are the rules the code is built around. The [claim ledger](docs/STATUS.md) says where each one has been
tested, and names any open defect.

* **No silent weakening.** A rule needing a capability the device lacks is rejected, or (allow rules only) left out
  *with a report*. Profiles are capability-checked at compile time.
* **No scripts in policy.** Strict, versioned data; unknown fields rejected.
* **Signed, platform-matched, replay-protected snapshots.** Trust is owner configuration; nothing promotes it.
* **Agents cannot authorize themselves.** Broadening needs the owner key; agents can only propose a diff and assert
  intent. The structured diff is conservative (unknown changes count as broadening), and grants keep their device
  and session scope through serialization. Tested in CI, not on an installed endpoint.
* **Isolation is sticky.** No heartbeat loss, restart, new policy or canary rollback reopens it.
* **Gaps are visible.** Sequence numbers, restart and gap records; enforcement never waits on logging.
* **No invented measurements.** No "0 bytes" without a measurement, never an intended upload size.

## Documentation

**Where things stand:** [Status and claim ledger](docs/STATUS.md) · [Support matrix](docs/support-matrix.md) ·
[Adversarial matrix](docs/adversarial-matrix.md) · [Source roadmap](docs/ROADMAP.md)

**Contracts and behavior:** [Protection contract](docs/protection-contract.md) ·
[Policy semantics](docs/policy-semantics.md) · [Contracts and fixtures](contracts/README.md) ·
[Temporary grants](docs/temporary-grants.md) · [Failure behavior](docs/failure-behavior.md) ·
[Threat model](docs/threat-model.md) · [Privacy](docs/privacy.md) · [UI evidence](docs/ui-evidence.md)

**Platforms:** [Linux](docs/platforms/linux.md) · [Proxy stream contract](docs/proxy-stream-contract.md) ·
[Linux activation journal](docs/linux-activation-journal.md) · [macOS](docs/platforms/macos.md) ·
[Fleet sync](docs/fleet-sync.md) · [Learning](docs/learning.md) · [DNS and Digital Kingdom](docs/integrations.md)

**Decisions:** [W09 ordinary apps on Linux](docs/decisions/W09-linux-ordinary-apps.md) ·
[W10 enforcement](docs/decisions/W10-enforcement.md) · [W10 BPF loader](docs/decisions/W10-increment-3-loader.md) ·
[W11 `CAP_SYS_PTRACE`](docs/decisions/W11-cap-sys-ptrace.md) · [Naming](docs/naming.md) ·
[OpenSnitch desk assessment](docs/platforms/opensnitch-adapter-feasibility.md) (superseded by W09)

**Testing and release:** [VPN test matrix](docs/vpn-test-matrix.md) · [Compatibility suite](docs/compatibility-suite.md) ·
[Feasibility checklist](docs/feasibility-checklist.md) (historical) · [Recovery drill](docs/recovery-drill.md) ·
[Recovery and update policy](docs/recovery-update-policy.md) · [Release engineering](release/README.md) ·
[Licensing](docs/licensing.md) · [Security](SECURITY.md)

## License

Apache-2.0. No code from GPL projects (LuLu, OpenSnitch) is included; see [docs/licensing.md](docs/licensing.md).
