# Recovery and update policy (MASTER_ROADMAP §17.2)

Status: **policy for the first releases; only experimental prereleases exist.** Items marked *not built* are requirements,
not features.

## Principles

1. **An update never disables enforcement.** An update outage, a failed download or a failed install leaves the
   installed version running with its last verified policy, and status says the update is stale.
2. **The app, service, extension, policy schema and stored state are one compatibility set.** A new binary
   validates the stored state before switching; a set it does not understand is refused visibly, never reset.
   Tested today for the activation journal: `state_left_by_a_newer_schema_is_kept_and_refused_not_reset`.
3. **Transitions are journaled and reconciled after interruption.** Policy activation already works this way
   ([linux-activation-journal.md](linux-activation-journal.md)); software updates must too (*not built*).
4. **Isolation, replay and trust state survive updates.** Replay high-water marks, trusted keys and an active
   emergency isolation are carried across every update and migration. Deleting anti-replay metadata is never a
   recovery step.
5. **Authorized recovery downgrade is a separate, explicit procedure** with owner authorization, not the side
   effect of installing an older package.
6. **A new binary does not inherit claims.** The release manifest lists which capabilities were tested at which
   commit; a claim tested elsewhere is labelled so.

## Release integrity

| Item | Status |
| --- | --- |
| macOS: Developer ID signing and notarization (`macos/scripts/release.sh`), cask with sha256 | scripted, never run (needs Robert's Apple credentials) |
| Linux: Arch `PKGBUILD` with checksums | present, not published |
| Release integrity: `SHA256SUMS`, keyless Sigstore signature over it (GitHub OIDC identity of `release.yml`), GitHub build-provenance attestation per asset | built in CI (`release` workflow) on main and `v*` tags, verified by `release/recovery-drill.sh integrity` with negative controls. Not policy authority; the owner policy key is a separate trust domain and is not used |
| CycloneDX SBOMs (each Rust workspace crate, each npm workspace) | generated in CI on every PR and push, with a coverage gate (`release/sbom-check.py`) |
| Updater metadata with role separation, freshness and rollback/freeze protection | *not built*; evaluate a maintained TUF implementation rather than a custom protocol |
| Dependency licence report and release manifest | generated in CI on every push (`release-engineering` and `release` workflows) and attached to each release |
| GitHub Actions pinned to commit SHAs | enforced in CI (`release/check-actions-pinned.py`) |
| Private mirror / offline import for self-hosted operation | *not built* |

## Local recovery (today)

Scripted drill with the CI-runnable part run on every PR: [recovery-drill.md](recovery-drill.md).

* **Linux:** `moatd recover isolate | clear-isolation | confirm | disable | resume` on the local socket (owner-only);
  an unconfirmed trial reverts on its own; a corrupt or unknown journal reports recovery-required and keeps the
  last verified snapshot enforced until a newer signed revision arrives.
* **macOS:** see [platforms/macos.md](platforms/macos.md); cache and trust reload are an open defect
  (`D-MAC-CACHE-TRUST`).
* **Uninstall:** the Arch package (`linux/packaging/arch/moat.install`) and the cask (`zap` stanza) define uninstall
  paths. Neither has been run on a real device, and what each leaves in the kernel or on disk is unverified.

## Update procedure (first releases, manual)

1. Read the release manifest and notes: which claims were tested on which versions, migrations, known gaps.
2. Install the new package; the service restarts and validates stored state.
3. If it reports recovery-required or refuses state: reinstall the previous package; state is untouched because a
   newer binary never rewrites state it does not understand and an older one refuses state it does not know.
4. Confirm status shows the same policy revision and coverage as before the update.
