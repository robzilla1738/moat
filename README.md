<div align="center">

# Moat

**Understand and control what software can send from your devices,<br>with stronger boundaries for the workloads you choose to protect.**

An open, self-hosted outbound firewall for people whose software increasingly acts on their behalf: coding agents,
MCP servers, package installers, local models, generated programs. One signed policy across your Macs and Linux
machines, enforced locally on each device, coordinated by an optional controller you run yourself.

[Status](docs/STATUS.md) · [Support matrix](docs/support-matrix.md) · [Protection contract](docs/protection-contract.md) · [Policy semantics](docs/policy-semantics.md) · [Threat model](docs/threat-model.md)

</div>

<p align="center">
  <img src="docs/screenshots/macos-overview-dark.png" alt="Moat for macOS: the Liquid Glass overview window, demo data" width="880">
</p>
<p align="center"><sub>The macOS app on macOS 26, captured from the real app window on the CI runner in demo mode (no signed install).</sub></p>

> **Read this first.** Moat is an **experimental build**. Nothing is supported on real devices: no claim is
> `supported_installed`, and every result so far comes from GitHub CI runners or unit tests. The Linux
> protected-session boundary passes on a CI runner kernel and as a packaged unit on an Ubuntu runner, but has not run
> on Omarchy. The macOS content filter has never run as a signed system extension. There is no fail-closed claim, no
> VPN-compatibility claim and no TLS interception. Phones and the TV get **DNS-only** coverage, labelled as such.

## Where Moat stands

The [claim ledger](docs/STATUS.md) is the source; this is its summary by release gate (MASTER_ROADMAP §13).

| Gate | Status | Blocked on |
| --- | --- | --- |
| **G0** truthful experimental build | **Not met.** Every Lane A defect from the baseline review is closed with a regression test. Three Mac/web defects are still open in the ledger. | `D-MAC-CACHE-TRUST`, `D-WEB-DEMO-SUCCESS`, `D-INCIDENT-ROUTING` |
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
| **Observed** | Moat sees a connection and records it. Nothing is blocked, and the UI says *permitted, not enforced*. | macOS, Linux |
| **Enforced** | Your signed policy decides; a deny happens at the OS hook before data passes. | macOS per-app (untested on device), Linux device/user-wide |
| **Protected session** | A boundary built **before the workload runs**, inherited by every child, escape-tested. Hostname rules for TCP are enforced by a per-session egress proxy (TLS SNI / HTTP CONNECT / Host, no TLS interception). | Linux `moat-launch` (cgroup v2 + nftables); proxy CI-tested, *untested* on Omarchy |

A launcher that only adds a label is an *instrumented* session, not a protected one, and Moat never calls it one.

## What it looks like

<table>
<tr>
<td width="58%"><img src="docs/screenshots/macos-activity-light.png" alt="macOS Activity, light"></td>
<td><img src="docs/screenshots/macos-menubar-dark.png" alt="macOS menu bar extra, dark"></td>
</tr>
<tr>
<td><sub><b>macOS Activity.</b> Blocked flows say <i>blocked before data was sent</i>; observed flows are never called allowed; bytes appear only when macOS reported them.</sub></td>
<td><sub><b>Menu bar extra.</b> Coverage at a glance, recent blocks, and Isolate this Mac behind a second explicit confirmation. Turning isolation off still needs the typed phrase in Recovery.</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/macos-onboarding-light.png" alt="macOS first-run onboarding: what Moat can claim"></td>
<td><img src="docs/screenshots/mobile-allow-once-dark.png" alt="Phone: allow once for this session"></td>
</tr>
<tr>
<td><sub><b>First-run onboarding.</b> Starts with what Moat can and cannot claim on this Mac, then walks through extension approval, the content filter and adding your signer key (you add it; the app only reads it).</sub></td>
<td><sub><b>Phone web UI.</b> "Allow once for this session" is bound to the incident, policy revision and session instance; stale approvals are rejected.</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/desktop-rules-dark.png" alt="Fleet rules"></td>
<td><img src="docs/screenshots/mobile-home-dark.png" alt="Phone home"></td>
</tr>
<tr>
<td><sub><b>Rules.</b> Every revision shows its diff, who authorized it, per-device delivery state, and what each platform had to leave out.</sub></td>
<td><sub><b>Home.</b> Which devices are covered, what is blocked, what needs a decision.</sub></td>
</tr>
</table>

**About these images.** The `macos-*.png` files are captured from the real Moat app window (`screencapture -l`) on
GitHub's `macos-26` runner, built unsigned with Xcode 26 and launched with `--demo`, so the data comes from the demo
client backed by the real `ControlHandler`, not from a running content filter
([`macos/scripts/capture-screenshots.sh`](macos/scripts/capture-screenshots.sh)). The window height is limited by the
runner's small display. The phone and desktop images are the fleet web UI rendered in CI from its demo build. More in
[docs/screenshots](docs/screenshots).

## What's in this build

* **macOS app in Liquid Glass.** Rebuilt for macOS 26: glass sidebar and toolbar, glass controls and morphing
  status, with macOS 14/15 fallbacks and support for Reduce Transparency, Increase Contrast and Reduce Motion.
  Builds and is captured in CI; not yet checked by eye on a real Mac.
* **Menu bar extra.** Status, recent blocks and a confirmed isolate, without opening the window.
* **First-run onboarding.** Honest coverage labels first, then extension approval, the content filter and signer
  key. The approval steps need a signed build on a real Mac and have not run there yet.
* **Linux timed rollback.** `moatd apply --trial-secs N` installs a trial revision that reverts on its own unless you
  run `moatd recover confirm`; `recover rollback` reverts now. The replay mark is kept, the first revision cannot be a
  trial, and rollback never touches isolation. Passes CI's netns suite and the recovery drill; untested on Omarchy.
* **Session hostname proxy (Linux).** Inside a protected session, TCP hostname rules are enforced by a per-session
  loopback proxy that reads TLS SNI, HTTP CONNECT or Host, resolves the name itself and connects only to what it
  resolved; nftables fences the listener. No TLS interception. UDP stays IP-only and domain fronting is still
  possible. Advertised as `untested` until run on Omarchy.

See [docs/STATUS.md](docs/STATUS.md) for exactly what each of these has and has not been proven on.

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

[Protection contract](docs/protection-contract.md) ·
[Failure behavior](docs/failure-behavior.md) ·
[Policy semantics](docs/policy-semantics.md) ·
[Threat model](docs/threat-model.md) ·
[Privacy](docs/privacy.md) ·
[VPN test matrix](docs/vpn-test-matrix.md) ·
[Compatibility suite](docs/compatibility-suite.md) ·
[Feasibility checklist](docs/feasibility-checklist.md) ·
[Licensing](docs/licensing.md) ·
[Linux](docs/platforms/linux.md) ·
[macOS](docs/platforms/macos.md) ·
[OpenSnitch adapter feasibility](docs/platforms/opensnitch-adapter-feasibility.md) ·
[Support matrix](docs/support-matrix.md) ·
[Recovery drill](docs/recovery-drill.md) ·
[Recovery and update policy](docs/recovery-update-policy.md) ·
[Naming](docs/naming.md) ·
[Security](SECURITY.md) ·
[**Status**](docs/STATUS.md)

## License

Apache-2.0. No code from GPL projects (LuLu, OpenSnitch) is included; see [docs/licensing.md](docs/licensing.md).
