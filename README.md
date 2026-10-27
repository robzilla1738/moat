<div align="center">

# Moat

**Understand and control what software can send from your devices,<br>with stronger boundaries for the workloads you choose to protect.**

An open, self-hosted outbound firewall for people whose software increasingly acts on their behalf: coding agents,
MCP servers, package installers, local models, generated programs. One signed policy across your Macs and Linux
machines, enforced locally on each device, coordinated by an optional controller you run yourself.

[Status](docs/STATUS.md) · [Protection contract](docs/protection-contract.md) · [Policy semantics](docs/policy-semantics.md) · [Threat model](docs/threat-model.md)

</div>

<p align="center">
  <img src="docs/screenshots/macos-overview-dark.png" alt="Moat for macOS: overview" width="880">
</p>

> **Read this first.** Moat states exactly what it covers and nothing more. The Linux protected-session boundary is
> proven in CI on a real kernel; the macOS content filter builds and is unit-tested but **has not yet run as a signed
> system extension on a real Mac**, so every macOS capability is labeled *untested*. There is no fail-closed claim,
> no VPN-compatibility claim, no TLS interception, and phones and the TV get **DNS-only** coverage, labeled as such.
> See [docs/STATUS.md](docs/STATUS.md) for every item.

## Three things, never blended

| | What it means | Where |
| --- | --- | --- |
| **Observed** | Moat sees a connection and records it. Nothing is blocked, and the UI says *permitted, not enforced*. | macOS, Linux |
| **Enforced** | Your signed policy decides; a deny happens at the OS hook before data passes. | macOS per-app (untested on device), Linux device/user-wide |
| **Protected session** | A boundary built **before the workload runs**, inherited by every child, escape-tested. | Linux `moat-launch` (cgroup v2 + nftables) |

A launcher that only adds a label is an *instrumented* session, not a protected one, and Moat never calls it one.

## What it looks like

<table>
<tr>
<td width="58%"><img src="docs/screenshots/macos-activity-light.png" alt="macOS activity"></td>
<td><img src="docs/screenshots/mobile-allow-once-dark.png" alt="Phone: allow once for this session"></td>
</tr>
<tr>
<td><sub><b>macOS Activity.</b> Blocked flows say <i>blocked before data was sent</i>; observed flows are never called allowed; bytes appear only when macOS reported them.</sub></td>
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

macOS screenshots are rendered in CI from demo data by the real `ControlHandler` (`macos/MoatKit/Tests/MoatUITests`).
More in [docs/screenshots](docs/screenshots).

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

## Guarantees the code enforces

* **No silent weakening.** A rule needing a capability the device lacks is rejected, or (allow rules only) left out
  *with a report*.
* **No scripts in policy.** Strict, versioned data; unknown fields rejected.
* **Signed, platform-matched, replay-protected snapshots.** Trust is owner configuration; nothing promotes it.
* **Agents cannot authorize themselves.** Broadening needs the owner key; agents can only propose a diff and assert
  intent, never a verified block.
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
[**Status**](docs/STATUS.md)

## License

Apache-2.0. No code from GPL projects (LuLu, OpenSnitch) is included; see [docs/licensing.md](docs/licensing.md).
