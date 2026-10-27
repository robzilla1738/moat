# VPN coexistence test matrix

**Status: nothing in this matrix has been run on Robert's devices.** Moat makes **no VPN compatibility claim** until
a row passes on real hardware with the exact versions recorded. Desktop enforcement is local (a content filter on
macOS, nftables on Linux) and does not add a full-tunnel VPN, but that architectural choice does not prove
coexistence.

Do **not** "fix" a failing row with a blanket allow for every VPN process, Apple process or tailnet destination. A
rule for the trusted Tailscale transport does not let an untrusted workload reach every peer or use the transport as
a proxy.

## Inputs to record before each run

macOS version and build · Tailscale distribution (App Store / standalone / open-source `tailscaled`) and version ·
Tailscale settings (MagicDNS, exit node, "use Tailscale DNS", LAN access) · Surfshark version and mode (WireGuard /
IKEv2, kill switch, Bypasser, CleanWeb) · Omarchy kernel, systemd and network stack (NetworkManager / iwd /
systemd-networkd) · Moat revision and policy revision.

## Matrix

Legend: ☐ not run · ✅ pass · ❌ fail (link the issue) · ➖ not applicable.

### macOS (`MoatFilter`)

| # | Scenario | Tailscale only | Surfshark only | Both | Notes / what to observe |
| --- | --- | --- | --- | --- | --- |
| M1 | Filter sees and attributes flows **before encryption** (app identity on the inner flow, not the VPN process) | ☐ | ☐ | ☐ | Activity shows the originating app for a curl to a public host. |
| M2 | Deny rule blocks a public destination while connected | ☐ | ☐ | ☐ | Blocked before data; the VPN stays up. |
| M3 | Tailnet peer access (MagicDNS name and 100.x IP) under a *private services only* profile | ☐ | ➖ | ☐ | Allowed only for named peers; the controller/admin address stays denied for workloads. |
| M4 | Direct vs DERP-relayed Tailscale paths | ☐ | ➖ | ☐ | No change in verdicts. |
| M5 | Exit node on / off | ☐ | ➖ | ☐ | Hostname evidence still present; scope classification correct. |
| M6 | Surfshark reconnect and kill switch | ➖ | ☐ | ☐ | No stuck flows; isolation still sticky; coverage stays truthful. |
| M7 | Surfshark Bypasser with Moat app excluded / included | ➖ | ☐ | ☐ | Document behavior; no claim either way until tested. |
| M8 | Split DNS / MagicDNS resolution while filtering | ☐ | ☐ | ☐ | Hostname evidence source recorded as `flow_api`. |
| M9 | Sleep / wake, network change (Wi-Fi ↔ Ethernet) | ☐ | ☐ | ☐ | Filter keeps running; no coverage claim without a fresh status. |
| M10 | IPv6 and UDP/QUIC through each VPN | ☐ | ☐ | ☐ | QUIC flows decided; denies hold. |
| M11 | Emergency isolation keeps chosen recovery path (e.g. SSH over tailnet) | ☐ | ➖ | ☐ | Only if the owner kept that path. |

### Linux / Omarchy (`moatd`)

| # | Scenario | Tailscale (`tailscaled`) | Surfshark (WireGuard) | Both | Notes |
| --- | --- | --- | --- | --- | --- |
| L1 | Protected session denied public egress through `tailscale0` and through the VPN interface | ☐ | ☐ | ☐ | nftables output hook sees the inner flow before tunnel encapsulation. |
| L2 | Tailnet SSH to named management peers allowed by a narrow rule | ☐ | ➖ | ☐ | |
| L3 | `tailscaled`'s own nftables/iptables rules and Moat's table coexist after restart of either | ☐ | ☐ | ☐ | Moat restores its table if removed and records it. |
| L4 | Exit node routes | ☐ | ➖ | ☐ | Scope classification of 100.64.0.0/10 stays `tailnet`. |
| L5 | Reboot ordering (moatd before/after VPN) | ☐ | ☐ | ☐ | Last valid policy enforced from boot. |

### Phones and TV (DNS-only)

| # | Scenario | Result | Notes |
| --- | --- | --- | --- |
| D1 | iPhone with Tailscale using the mini's resolver via tailnet DNS | ☐ | Per-client identity preserved? |
| D2 | Android TV (confirm TCL model / Android version first) with Tailscale installed | ☐ | Streaming auth, CDN rotation, casting. |
| D3 | Public secondary resolver configured → bypass documented | ☐ | Expected limitation: DNS-only cannot stop direct-IP or DoH. |

## Recording a result

Add a row note with versions, date, Moat commit, and a link to the raw evidence (Activity export, `moatd status`,
`nft list table inet moat`). Then update [STATUS.md](STATUS.md). The UI keeps saying "untested" for VPN coexistence
until the relevant rows pass.
