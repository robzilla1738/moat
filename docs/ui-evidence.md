# What the web UI claims, and from which evidence (W08)

The web UI has two explicit modes. Neither borrows from the other.

| Mode | How you get it | What it shows | What its buttons do |
|---|---|---|---|
| Demo | the static demo build (for GitHub Pages once Pages is enabled, [#1](https://github.com/robzilla1738/moat/issues/1); also the web tarball of each release) or **Explore sample data** on the sign-in screen | fixed sample data, labeled "Sample data" on every screen | nothing is sent; each action says "demo: simulated" |
| Live | sign in with a controller token | only what the controller API returned | authenticated requests with version preconditions; states come from endpoint receipts |

A live page that cannot load shows the failure. It never shows sample data. A live page that loaded once and then
lost the controller keeps the last data, says how old it is ("Not current"), and pauses actions.

## Action states

| State | Meaning | Evidence |
|---|---|---|
| sending | the request has not been answered | none |
| pending | the controller accepted and the signer signed revision N; no endpoint has reported applying it | `POST /v1/actions/allow-once` answer, `GET /v1/grants/:id` |
| active | an endpoint receipt names a revision that carries the grant | `device_revisions` row with state `applied`/`trial` for a revision ≥ the grant's |
| rejected | the controller refused (stale, forbidden, invalid) or the endpoint rejected/rolled back the revision | HTTP 4xx, or a `rejected`/`rolled_back` receipt |
| failed | the request never reached the controller | network error; nothing changed |
| expired / revoked | the grant's original deadline passed, or the owner revoked it | controller clock vs. the stored `expires_at` |

"Active" is the endpoint's own receipt. It is not independent proof of every packet verdict.

The authorizer shown for a revision (owner key, narrowing, temporary-grant overlay) is the signer's recorded answer
(`policy_revisions.authorized_by`). Revisions published before this column existed show "authorizer not recorded".

## Preconditions

* Allow once: incident id + incident revision + policy revision the owner saw. Any change → 409, shown as "Refused as stale"; the view refreshes.
* Keep blocked / acknowledge: `expected_revision` (the incident revision) is required (428 without it, 409 when changed).
* Rollback: prepares a proposal against the current revision; approval re-checks the base revision. A broadening
  rollback needs an owner-key authorization made off the page (`moat-controller owner-authorize`), pasted back. The owner key never enters the browser.

## Freshness

Freshness is computed in the browser from the controller's clock: age = (controller time at fetch − device
`last_seen_at`) + time this page has held the snapshot. A device older than 10 minutes shows **Unknown**, whatever
coverage it last claimed. A skewed browser clock cannot make old evidence look current.

## Notification references

`#/r/<ref>` resolves the opaque reference through `GET /v1/r/:ref`. The reference is bound to one incident id when
the notification is queued. New, reordered or resolved incidents never retarget it; a deleted incident or unknown
reference opens "Notification not found" and nothing else. Tests: `controller/test/controller.test.ts` ("W08: a
notification reference opens exactly its incident…") and the live e2e; `D-INCIDENT-ROUTING` closed (controller
40577605234, web 40577605299).

Floods (#60): an unchanged incident notifies once; when one subject raises many incidents, three are notified
individually and the rest collapse into one summary per 10-minute window. The summary's reference opens the incident
that tripped the threshold; every incident stays listed. A dedicated grouped-incidents view is not built yet
(`controller/test/notification-floods.test.ts`).

## Untrusted display data

App names, hostnames, session ids, rule text, agent intent and explanations are rendered as text. Invisible and
direction-changing characters are shown as `⟨U+202E⟩`-style escapes with a visible caution, mixed-script and
punycode names are flagged, and absurd lengths are shortened with a note.

## Unavailable on purpose

* Allow once for ordinary apps (no protected session): unavailable until device-scoped app identity is proven (W03/W07).
* Allow once for rule-scoped counters (no destination recorded): unavailable; make a reviewed policy change.
* Every owner action for viewer tokens, while the controller is unreachable, or while the view is not current.

## Tests

* `web/src/truth.test.tsx` (vitest): hostile markup, look-alike identifiers, freshness, evidence-only action states, demo/live separation.
* `web/e2e/live.e2e.ts` (Chromium via Playwright, CI job `live-e2e`): the production build against a real controller,
  signer, Rust `moatctl` and device-signed sync. Screenshots: `docs/screenshots/live-*.png`.
* Ledger: `fleet.web.live-actions`, `implemented_unproven`, component evidence (web 40577605299); `D-WEB-DEMO-SUCCESS`
  closed. No phone and no real endpoint have been used.

Later surfaces follow the same rules: the Apps-first standalone views (W12), reconciliation and recovery states from
W05/W06 events (#36), learning review (W14, [learning.md](learning.md)) and DNS-only devices (W16,
[integrations.md](integrations.md)).

## Screenshots

Every image in [`docs/screenshots`](screenshots) is a CI capture on demo data, not a real device. Light and dark are
captured for the same screens so the README can follow the reader's GitHub theme.

| Surface | Light | Dark | Source |
|---|---|---|---|
| Desktop web, Apps (landing) | [desktop-home-light](screenshots/desktop-home-light.png) | [desktop-home-dark](screenshots/desktop-home-dark.png) | `web/scripts/screenshots.mjs` (demo build, Chromium, axe-core AA check) |
| Desktop web, Overview (full page) | [desktop-overview-light](screenshots/desktop-overview-light.png) | [desktop-overview-dark](screenshots/desktop-overview-dark.png) | same |
| Desktop web, Activity / Rules / Devices / Packs | [activity](screenshots/desktop-activity-light.png) · [rules](screenshots/desktop-rules-light.png) · [devices](screenshots/desktop-devices-light.png) · [packs](screenshots/desktop-packs-light.png) | [activity](screenshots/desktop-activity-dark.png) · [rules](screenshots/desktop-rules-dark.png) · [devices](screenshots/desktop-devices-dark.png) · [packs](screenshots/desktop-packs-dark.png) | same |
| Phone, Apps / Overview | [home](screenshots/mobile-home-light.png) · [overview](screenshots/mobile-overview-light.png) | [home](screenshots/mobile-home-dark.png) · [overview](screenshots/mobile-overview-dark.png) | same, 390 × 844 at 3× |
| Phone, Activity / Allow once / Coverage / DNS device | [activity](screenshots/mobile-activity-light.png) · [allow once](screenshots/mobile-allow-once-light.png) · [coverage](screenshots/mobile-coverage-light.png) · [DNS device](screenshots/mobile-device-dns-light.png) | [activity](screenshots/mobile-activity-dark.png) · [allow once](screenshots/mobile-allow-once-dark.png) · [coverage](screenshots/mobile-coverage-dark.png) · [DNS device](screenshots/mobile-device-dns-dark.png) | same |
| Phone, Learning | [learning](screenshots/mobile-learning-light.png) | [candidate](screenshots/mobile-learning-candidate-dark.png) | same |
| Reduced transparency | [mobile-home-reduced-transparency-light](screenshots/mobile-home-reduced-transparency-light.png) | | same, `prefers-reduced-transparency: reduce` |
| Live UI against a real controller | `live-*.png` | | `web/e2e/live.e2e.ts` (CI job `live-e2e`; a controller on the CI runner, not a fleet) |
| macOS app window | [apps](screenshots/macos-apps-light.png) · [activity](screenshots/macos-activity-light.png) · [coverage](screenshots/macos-coverage-light.png) · [what changed](screenshots/macos-whatChanged-light.png) | [apps](screenshots/macos-apps-dark.png) · [activity](screenshots/macos-activity-dark.png) · [rules](screenshots/macos-rules-dark.png) · [this computer](screenshots/macos-devices-dark.png) | `macos/scripts/capture-screenshots.sh` on the `macos-26` runner, unsigned build, `--demo` |
| macOS menu bar panel, onboarding, local rule | [menubar](screenshots/macos-menubar-light.png) · [onboarding](screenshots/macos-onboarding-light.png) · [local rule](screenshots/macos-localrule-light.png) | [menubar](screenshots/macos-menubar-dark.png) · [onboarding](screenshots/macos-onboarding-dark.png) · [local rule](screenshots/macos-localrule-dark.png) | same |

The design rules these screens follow, including that every chart is drawn from recorded fields and demo charts are
tagged "Sample data", are in [design.md](design.md).
