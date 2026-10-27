# Privacy and audit log

Moat is self-hosted. Logs stay on the owner's devices and controller. There is no hosted service and no telemetry to
the project.

## What is recorded

Per connection attempt (within the declared sensor boundary): device and boot sequence number, process instance and
app identity (signing ID / team / path where available), session evidence and whether it is verified, destination
address / port / protocol, hostname evidence **with its source and confidence**, decision, winning rule and policy
revision, times, measurement source and counter scope, and coverage status at the time.

DNS observations are kept **separate** from connections. Attempted, allowed, blocked and terminated are distinct
states. Gaps, restarts and dropped ranges are records too.

## What is not recorded by default

Payloads, credentials, environment variables, URL paths and query strings, full command lines, and request bodies.
Moat does no TLS interception, so it never sees them. Executable paths are kept; arguments are not.

Destination history and DNS names are still sensitive: treat the controller's data directory like a password store
(encrypted disk, encrypted backups, owner-only access).

## Retention

Pilot default: **30 days of raw flow records, 90 days of rollups**, configurable, with a disk quota and visible
retention boundaries (`controller/src/flows.ts`). Endpoint spools have their own quota (Linux default 256 MiB);
overflow becomes a visible gap, never silent loss. Sizing comes from pilot measurements, not an invented flow rate.

## Notifications

Notifications are optional. The ntfy and webhook notifiers carry **only an opaque incident reference**;
details are fetched from the controller over the tailnet by an authenticated client. Using ntfy's APNs-connected
upstream for instant iPhone delivery is an optional cloud transport dependency and is disclosed as such; without it,
the web UI and foreground polling still work, and instant background delivery is not promised.

## Shared intelligence

Off by default. No community feed ships in this release. If one is added it will be curated, signed, versioned,
reversible, opt-in, previewable, data-only, and will never upload raw logs, private domains, repository names,
prompts, model inputs, user identifiers or full paths.

## Enrichment

Provider, ASN, region and GeoIP datasets are **downloaded in batches** (importers in `moat-core` for AWS ip-ranges, GCP cloud.json and CSV);
destinations are never sent one by one to a public lookup service. Every fact shows its source, date and
uncertainty.

## Local language models

Optional, explanation-only. A model may help read a timeline; it never decides access, infers intent as fact,
executes responses, or sends logs to a cloud model. Alert text is produced by deterministic templates
(`core/moat-core/src/explain.rs`).
