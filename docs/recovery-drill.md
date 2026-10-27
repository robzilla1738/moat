# Local recovery drill (W15, MASTER_ROADMAP §15.4, §17.2)

A scripted, repeatable drill for getting a device back to a known state when a policy, the daemon, stored state
or an update goes wrong, **without the controller**. One script, two parts:

```sh
release/recovery-drill.sh integrity <dir-with-release-assets>       # before installing anything
sudo release/recovery-drill.sh local <dir-with-moatd-and-moatctl>   # Linux, root, nf_tables, cgroup v2
```

Both print one `PASS`/`FAIL` line per step and exit non-zero if any step failed. CI runs both on every PR and push
(`release` workflow: `build` and `sign` jobs run `integrity`, `recovery-drill` runs `local`). Passing in CI is
**`native_ci` evidence on a GitHub runner**, not proof on Robert's devices: the device-only steps are at the end.

Related: [recovery and update policy](recovery-update-policy.md) · [Linux activation journal](linux-activation-journal.md)
· [failure behavior](failure-behavior.md) · [support matrix](support-matrix.md).

## Part 1: verify a release before installing it (`integrity`)

Every release carries `SHA256SUMS` (every asset), `SHA256SUMS.sigstore.json` (a keyless Sigstore signature over
`SHA256SUMS`, made by the `release` workflow's GitHub Actions OIDC identity) and a GitHub build-provenance
attestation per asset (`provenance.sigstore.json` is a copy of the attestation bundle).

| Step | Check | Negative control |
| --- | --- | --- |
| 1 | `sha256sum --strict -c SHA256SUMS`; no asset is missing from the list | an asset with one byte appended fails |
| 2 | `cosign verify-blob --bundle SHA256SUMS.sigstore.json` with identity `https://github.com/robzilla1738/moat/.github/workflows/release.yml@refs/(heads/main\|tags/v…)` and issuer `https://token.actions.githubusercontent.com` | an edited `SHA256SUMS` fails; another signer identity fails |
| 3 | `gh attestation verify <asset> --repo robzilla1738/moat --signer-workflow robzilla1738/moat/.github/workflows/release.yml` for every asset | the tampered asset has no attestation |

Manual equivalent, for one asset:

```sh
sha256sum --strict -c SHA256SUMS
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/robzilla1738/moat/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
gh attestation verify moat-linux-x86_64-<version>.tar.gz --repo robzilla1738/moat
```

**Trust domains.** These signatures say *which workflow in which repository built these bytes from which commit*.
They are not policy authority. The owner policy key (which signs policy snapshots on the owner's devices) is a
separate trust domain (§17.1): it is never present in CI and is not used to sign releases, and a release signature
cannot authorize a policy, a grant or a new trusted key. There is no Apple Developer ID signature or notarization and
no signed Arch package yet ([#2](https://github.com/robzilla1738/moat/issues/2),
[#5](https://github.com/robzilla1738/moat/issues/5)).

## Part 2: Linux local recovery (`local`)

Runs the real `moatd` and `moatctl` in a throwaway pair of network namespaces with a temporary state directory, so it
never touches the host's network or `/var/lib/moat`. The procedure below is what an owner runs on a device; the script
runs the same commands and checks the result after each one.

| # | Situation | Owner action (on the device, no controller) | What must be true afterwards |
| --- | --- | --- | --- |
| 0 | baseline | `moatd trust owner.key.pub`; `moatd apply signed.json` | revision confirmed, enforced; ordinary traffic flows (observe profile) |
| 1 | something is exfiltrating; act first | `sudo moatd recover isolate [--keep CIDR]` | peer unreachable, loopback works; **isolation survives the daemon being killed and restarted**; `recover status` reports it without the daemon and without root; only `recover clear-isolation` reopens |
| 2 | Moat itself is in the way (daemon stopped or wedged) | `sudo moatd recover disable --reason "…"` | enforcement table removed **with the daemon stopped**; a restarted daemon honours the disable and does not reinstall the table; `recover resume` re-enforces the last valid revision |
| 3 | a bad policy revision | apply with `--trial-secs N`; `sudo moatd recover rollback` to revert now | an unconfirmed trial reverts on its own; rollback returns to the previous revision; the reverted revision cannot be replayed; the replay high-water is not lowered; `recover confirm` with nothing on trial is refused |
| 4 | corrupt activation journal | none needed to stay safe; apply a newer signed revision to clear | `recovery-required`, the last verified revision stays enforced (table kept, not weakened), the bad file is kept as `activation.json.corrupt`, a newer signed revision restores `confirmed` |
| 5 | an update went wrong; you reinstalled the previous version | reinstall the previous package; apply a newer signed revision | the older binary refuses state written by the newer one (`unknown schema`), keeps enforcing the last verified revision, keeps the newer state **byte for byte**, still refuses replays, and a newer signed revision restores a known state |
| 6 | a snapshot signed by a key the device does not trust | none | refused (`signed by unknown key`); the current revision stays |

Owner-key loss is not bypassed by any step: a device only accepts snapshots signed by a key it was told to trust
(`moatd trust`). Restoring the owner key from its backup, or trusting a new owner key on each device locally, is the
recovery; deleting anti-replay or trust state is never a step.

What the script does **not** show: that the installed systemd unit on Omarchy behaves the same (the `installed`
job in `linux-endpoint` covers the packaged unit on Ubuntu, not Omarchy), and that the recovery commands are
reachable when the device has no network at all (they use only the local socket and the state directory, but this is
not separately tested).

## Device-only steps (not run in CI; results go in the claim ledger with date and versions)

| Platform | Step | Blocked on |
| --- | --- | --- |
| Omarchy | Install the Arch package; run `sudo release/recovery-drill.sh local /usr/bin` (moatd stopped via `systemctl stop moatd` for steps 2, 4, 5); then reboot and confirm isolation and the last revision survive the reboot | Robert's Omarchy machine ([#6](https://github.com/robzilla1738/moat/issues/6)) |
| Omarchy | Package downgrade: install release N, apply a revision, install N-1, confirm step 5's behaviour; uninstall and record what is left in nftables, cgroups and `/var/lib/moat` | [#5](https://github.com/robzilla1738/moat/issues/5), [#6](https://github.com/robzilla1738/moat/issues/6) |
| macOS | Signed install; turn the content filter off in System Settings and confirm the app reports it; `systemextensionsctl` removal; trust reload after the owner key changes; recovery card from the app | Developer ID ([#2](https://github.com/robzilla1738/moat/issues/2)), clean second Mac ([#7](https://github.com/robzilla1738/moat/issues/7)) |
| Fleet | 24-hour controller outage: endpoints keep enforcing, history shows the gap, no state becomes green or current | controller on the mini (G3) |
| Phone | Emergency isolate from the phone, then clear it locally with the controller down | G3 |

## Recording a run

Record each device run in `docs/claim-ledger.json` as a result for the matching claim, with environment
(`omarchy-installed`, `mac-signed-installed`), commit, date and the script output. A CI pass never promotes a claim
to supported.
