# Support matrix

**There are no supported configurations yet.** Moat is an experimental build: no claim in the
[claim ledger](claim-ledger.json) is `supported_installed` (see [STATUS.md](STATUS.md)). This page says which
platforms are targeted, what has been exercised where, and what end of support will mean, so that nothing is
assumed supported because it builds.

Prereleases (`v0.1.0-alpha.*`) ship Linux x86_64 binaries as an archive (not a signed package), source and web
tarballs, SBOMs and the release manifest. No macOS build is published until Developer ID signing exists.

A row becomes **supported** only when its claims are `supported_installed`: installed or real-workflow evidence,
dated, on that exact environment, with no open defect. The release manifest
([release/manifest.py](../release/manifest.py)) lists, per build, which claims were tested at which commit.

## Platforms

| Platform | Component | Status | Exercised on | Not yet exercised |
| --- | --- | --- | --- | --- |
| Linux, Omarchy (Arch), systemd | `moatd`, `moat-launch`, `moatctl` (Arch `PKGBUILD`, `moatd.service`) | **target, unproven** | GitHub runner ubuntu-26.04, kernel 7.0, cgroup v2, nftables 1.1.6: netns enforcement, packaged unit under systemd, observe-only inventory, bpftrace connect attribution | Robert's Omarchy machine: installed unit, real `moat-launch -- claude`, VPN coexistence |
| Linux, other systemd distributions | same | **not targeted** | CI runner only | everything installed |
| macOS 14+ (deployment target 14.0; cask template says Ventura or later, to reconcile before release) | Moat.app + NEFilterDataProvider system extension, Homebrew cask | **target, unproven** | GitHub macos-26 runner, unsigned build and unit tests | signed/notarized install, extension approval, reboot/recovery/upgrade/uninstall on a real Mac |
| Controller (Node 22.18+) | `controller/` | **experimental** | ci-node-22 tests against the Rust `moatctl` | a real fleet across an outage |
| Web UI | `web/` | **experimental** | CI build, axe-core contrast checks, live UI against the controller in CI | real phone use |
| Windows | none | **not targeted** | — | — |

## Capability cells

The claim ledger is the source; summarised here by kind.

| Capability | Linux | macOS |
| --- | --- | --- |
| Protected sessions (cgroup v2 + nftables, egress proxy) | implemented_unproven (native CI) | sessions refused at launch (no session enforcement on macOS) |
| Ordinary-app rules | **unsupported_rejected** (no proven hook; [W10 decision](decisions/W10-enforcement.md)) | implemented_unproven (component CI, never run signed) |
| Ordinary-app inventory | observe_only, implemented_unproven | via the filter extension, unproven |
| Activation journal, trial and rollback | implemented_unproven (fault-injected, native CI) | implemented_unproven (unit tests in macOS CI: canary rollback, first canary refused, verified restoration; never run signed) |
| VPN coexistence | not run | not run |

## Versions and end of support

* **Before 1.0:** only the latest commit on `main` receives fixes. No backports.
* **First releases:** each release lists the exact OS versions and kernels its claims were tested on (release
  manifest). A newer OS version is *unverified* until a dated result exists; it is not assumed to inherit claims.
* **End of support:** decided per platform version and announced in release notes at least one release ahead. When
  an OS version leaves support, its rows move to "not supported" here and its claims are dropped from the next
  manifest; the endpoint keeps enforcing its last verified policy and says that the platform is unsupported, it does
  not disable protection.
* Security reports: [SECURITY.md](../SECURITY.md).
