# Release engineering

Run by `.github/workflows/release-engineering.yml` and `.github/workflows/release.yml` on every push and PR; outputs are uploaded as artifacts. A `v*` tag on green main publishes a prerelease with all of them, signed (keyless Sigstore + build-provenance attestations; the owner policy key is never used).

| Script | What it does |
| --- | --- |
| `manifest.py` | Release manifest from `docs/claim-ledger.json`: every claim with disposition, evidence, environment, the commit and run of its last result, and whether that result was produced at a commit this build contains. Fails if a supported claim breaks a release rule. |
| `license-gate.py` | Dependency licence report (Rust via `cargo deny list`, npm via `license-checker`) and the copyleft gate. `--self-test` runs its negative controls. |
| `sbom.sh`, `sbom-check.py` | CycloneDX SBOMs (each Rust workspace crate, each npm workspace) and the coverage gate (`--self-test` for negative controls). |
| `recovery-drill.sh` | `integrity` (checksums, Sigstore signature, attestations) and `local` (Linux recovery in a netns); see [docs/recovery-drill.md](../docs/recovery-drill.md). |
| `notes/<tag>.md` | Release notes; the `release` workflow refuses to publish a tag without them. |
| `check-actions-pinned.py` | Fails if any workflow uses a third-party action by tag or branch instead of a 40-character commit SHA. |

Policies: [docs/recovery-update-policy.md](../docs/recovery-update-policy.md), [docs/support-matrix.md](../docs/support-matrix.md),
[docs/licensing.md](../docs/licensing.md), [SECURITY.md](../SECURITY.md), naming: [docs/naming.md](../docs/naming.md).

Updating a pinned action: resolve the tag to its commit (`git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>`,
using the `^{}` line for annotated tags) and keep the tag as a trailing comment.
