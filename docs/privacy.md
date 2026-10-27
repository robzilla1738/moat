# Privacy and audit log

Moat is self-hosted. Logs stay on the owner's devices and controller. There is no hosted service and no telemetry to
the project. Nothing on this page has been checked on a real deployment yet; it describes what the code records, as
tested in CI.

## What is recorded

Per connection attempt (within the declared sensor boundary): device and boot sequence number, process instance and
app identity (signing ID / team / path where available), session evidence and whether it is verified, destination
address / port / protocol, hostname evidence **with its source and confidence**, decision, winning rule and policy
revision, times, measurement source and counter scope, and coverage status at the time.

Linux session proxy decisions also record whether a name was looked up (`dns_lookup`: refused before lookup, allowed
name, or address-rules exposure), the address the client dialed when it differs, and every stream Moat ended with its
reason (`stream_terminated`, W05).

Linux ordinary-app inventory (W10, observe-only) records per connection: executable path (and whether it was
replaced on disk), process start generation, uid, cgroup, and for interpreters the script argument (the first
non-option argument, at most 256 characters, low confidence). A socket whose owner cannot be found is recorded with
`identity: null` and a reason. Loss is recorded as `inventory_loss`.

DNS observations are kept **separate** from connections, per resolver and client (W16). Attempted, allowed, blocked
and terminated are distinct states. Gaps, restarts and dropped ranges are records too.

## What is not recorded by default

Payloads, credentials, environment variables, URL paths and query strings, full command lines, and request bodies.
Moat does no TLS interception, so it never sees them. Executable paths are kept; arguments are not, except the
interpreter script argument above.

During the W09 experiment, OpenSnitch populated the **full process environment** (tokens and keys included) in 1052
of 1224 records; the harness redacts it before writing anything, and this was one reason it was not adopted
([decision](decisions/W09-linux-ordinary-apps.md)). Moat's own inventory reads no environment.

Destination history and DNS names are still sensitive: treat the controller's data directory like a password store
(encrypted disk, encrypted backups, owner-only access).

## Retention

Pilot default: **30 days of raw flow records, 90 days of rollups**, configurable, with a disk quota and visible
retention boundaries (`controller/src/flows.ts`). Endpoint spools have their own quota (Linux default 256 MiB,
`--spool-mib`); overflow evicts the oldest unacknowledged data with an exact `gap` record, never silent loss (W13).
Sizing comes from pilot measurements, not an invented flow rate. No pilot has run yet.

Learning captures (W14) read the flow store only, are bounded to one device, one executable identity, one workflow
and one network context, at most 8 hours and 20 000 records, and keep nothing beyond what the flow store already
holds.

## Notifications

Notifications are optional. The notifiers carry **an opaque incident reference and no incident details**
(`controller/src/notify.ts`): ntfy gets a fixed message ("Moat needs a decision") plus the reference and link; a
webhook gets the reference, link, notification kind (for example `notification_flood`) and urgency, HMAC-signed.
Details are fetched from the controller over the tailnet by an authenticated client. A flood summary carries the
same fields (#60). Using ntfy's APNs-connected upstream for instant iPhone delivery is an optional cloud
transport dependency and is disclosed as such (decision [#4](https://github.com/robzilla1738/moat/issues/4)); without
it, the web UI and foreground polling still work, and instant background delivery is not promised.

## DNS resolvers and Digital Kingdom

* Resolver credentials (an AdGuard Home password, a Pi-hole app password) are read from files at startup. They are
  not stored in the controller database and no API returns them. The adapters only read.
* The Digital Kingdom feed sends only enrolled endpoints' own policy decisions and sensor availability. Agent intent
  text is not sent, DNS-only evidence (`dns_blocked`) is not sent, and events for anything that is not an enrolled
  endpoint are dropped and counted ([integrations](integrations.md)). Both integrations are off unless configured.

## Shared intelligence

Off by default. No community feed ships in this release. If one is added it will be curated, signed, versioned,
reversible, opt-in, previewable, data-only, and will never upload raw logs, private domains, repository names,
prompts, model inputs, user identifiers or full paths.

## Enrichment

Provider, ASN, region and GeoIP datasets are **downloaded in batches** (importers in
`core/moat-core/src/enrichment.rs` for AWS ip-ranges, GCP cloud.json and CSV); destinations are never sent one by one
to a public lookup service. Every fact shows its source, date and uncertainty.

## Local language models

Optional, explanation-only. A model may help read a timeline; it never decides access, infers intent as fact,
executes responses, or sends logs to a cloud model. Alert text is produced by deterministic templates
(`core/moat-core/src/explain.rs`).

## Releases

Release artifacts carry SBOMs, a licence report and build provenance (W15). Building or verifying a release sends
nothing about any user's deployment anywhere.
