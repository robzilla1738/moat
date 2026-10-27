# Moat design system

Moat's UI on the web (phone PWA and desktop dashboard) and on macOS shares one calm "bento" system: a cool-grey
canvas, opaque cards with hairline borders and very soft shadows, a periwinkle/indigo accent with teal and amber as
secondary tones, crisp Inter type and tabular figures. Light mode is first-class; dark mode is a separately tuned
palette, not an inversion.

Sources of truth:

| What | Where |
|---|---|
| Colour, type, radius and spacing tokens | [`brand/design-tokens.json`](../brand/design-tokens.json) |
| Web CSS variables (generated) | [`web/src/tokens.css`](../web/src/tokens.css) |
| macOS colour sets, AppIcon, menu bar template (generated) | [`macos/Moat/App/Assets.xcassets`](../macos/Moat/App/Assets.xcassets) |
| macOS palette in code (kept in sync, checked) | [`macos/MoatKit/Sources/MoatUI/Theme.swift`](../macos/MoatKit/Sources/MoatUI/Theme.swift) |
| The mark and icons | [`brand/`](../brand) |

`node web/scripts/brand.mjs` regenerates everything from the SVGs and the token file (`--tokens` skips the rasters
and needs no browser). `web/src/tokens.test.ts` fails when `tokens.css` or `Theme.swift` drift from the token file,
and checks that every text tone meets WCAG AA on its card surface in both appearances.

## The mark

![Moat mark](../brand/png/moat-mark-light-256.png)

A keep (three merlons, walls, a round-topped gate) inside a moat ring. The ring is open only below the gate: the one
supervised way out. That is what Moat is, an egress gate around your Digital Kingdom.

* Geometry: a 24-unit grid; ring outer radius 10.75, inner 8.85; the gap is exactly the gate's width (2.9). It stays
  legible at 16 px because it is two solid shapes with no hairlines.
* Variants: `moat-mark.svg` (one colour, `currentColor`), `moat-mark-light.svg` / `moat-mark-dark.svg` (accent keep,
  accent-to-teal ring), `moat-icon.svg` (rounded square: favicon, apple-touch, PWA), `moat-icon-maskable.svg`
  (full bleed, mark in the safe zone), `moat-app-icon-macos.svg` (macOS icon grid: 824 px body, 100 px margin).
* Menu bar: a template image (black + alpha, 18 pt) that macOS tints. When coverage needs attention the coverage
  symbol replaces the mark, so the status item never hides a problem behind the logo.
* Clear space: half the mark's width on every side. Do not rotate, outline, add effects or recolour the ring and keep
  separately outside the defined variants.

## Colour

| Token | Light | Dark | Use |
|---|---|---|---|
| `bg` | `#F3F4F8` | `#0C0E14` | canvas |
| `surface` / `-2` / `-3` | `#FFFFFF` / `#F7F8FB` / `#EDEFF5` | `#151821` / `#1A1E29` / `#222734` | cards, insets, tracks |
| `border` / `-strong` | `#E3E6EE` / `#CDD2DE` | `#252A37` / `#353B4B` | hairlines, inputs |
| `text` / `text-2` / `muted` | `#0F1222` / `#3A4055` / `#5D6478` | `#ECEEF5` / `#C3C8D6` / `#969DB0` | copy |
| `accent` | `#4F46E5` | `#A5A8FF` | links, selection, focus |
| `accent-strong` | `#4F46E5` | `#4F4FDC` | solid fills carrying text (primary buttons, current-version chip, macOS prominent buttons, sidebar selection); ≥ 5:1 with its text in both appearances |
| `accent-soft` | `#EEF0FF` | `#23264A` | selected rows, announcement banners |
| `chart-1` / `-2` / `-3` | `#8B8FF7` / `#5CC8B4` / `#F5B83D` | `#7C80F0` / `#3FBFA9` / `#E9A93A` | observed / allowed / heat |
| `green` `red` `amber` `blue` `violet` `teal` | AA on white | AA on `surface` | status text and chip tints |

Dark mode is tuned on its own: lighter, less saturated status tones, a periwinkle accent, near-zero shadows with a
1 px inner highlight, and the same hierarchy of surfaces.

### Status is never colour alone

Every status chip pairs an icon with its label (web `Badge`, macOS `Pill`): green ✓, red ✕, amber ⚠, blue ⓘ,
violet globe, and specific icons for coverage (lock for protected session, shield for enforced, eye for monitoring,
globe for DNS only, ⚠ degraded, wrench recovery required, undo rollback pending, ? unknown) and support
(✓ supported, ⚠ partial, clock "needs device proof", − not available). Neutral chips (counts, ids) carry text only.

## Type

Inter Variable (`cv11`, `ss01`, `ss03`) on the web; the system font (SF Pro) on macOS. Every figure uses tabular
numerals.

One scale for both platforms (web `--t-*`, macOS `TypeScale.*`), from `brand/design-tokens.json`:

| Token | Size | Role |
|---|---|---|
| `xs` | 12 | chips, fine print |
| `sm` | 13 | secondary text, labels, list sub lines |
| `md` | 15 | body, card titles, buttons |
| `lg` | 17 | section headers |
| `xl` | 20 | detail titles |
| `2xl` | 28 | page titles on phones |
| `3xl` | 34 | page titles on desktop, big figures |

Weights: regular 450, medium 560, semibold 640, bold 700. Spacing uses one scale too (4, 8, 12, 16, 20, 24, 32,
40 px; web `--s-*`, macOS `Space.*`). `web/src/styles.test.ts` fails on any raw colour, font size or off-scale
spacing in `styles.css`.

## Layout and components

* **Bento grid**: 12 columns from 1180 px, 6 from 720 px, one column on phones; 16 px gaps. Overview and Apps are
  bento grids; other screens keep a 960 px reading column with the same cards.
* **Card**: radius 14 (inner elements 10), 1 px border, soft shadow (light only), 20 px padding. A card title can
  carry a quiet qualifier line ("Endpoint rollups | last 24 hours").
* **KPI tile**: chip label with icon, big tabular figure, a sub line, and a tiny chart (sparkline or ring) when there
  is a real series behind it.
* **Charts**: bar strip (hourly allowed / observed / blocked), heat grid (verdict × 4-hour window, each row scaled to
  its own peak), honeycomb (blocked attempts per hour, periwinkle to amber, current hour outlined), progress rings
  (devices with current coverage; endpoint receipts for the latest revision), evidence-age bars (each device's last
  report against the 10-minute freshness limit), ranked list (apps by recorded flows), and on macOS a flow strip (one
  tick per recent flow record, coloured by verdict).
* **Banners**: soft-tinted, with an icon: "Sample data" (accent) and "Not current" (amber).

## Each view's job

Every view answers one question and shows only what helps answer it. Anything else moves to the view whose job it
is, or behind Details.

| View | The question it answers | What it shows first |
|---|---|---|
| **Apps** (home) | What needs me now? | A coverage banner only when a device needs attention; "Needs your decision" (at most two decision cards, then "All N"); "Needs a look"; otherwise "All clear". Then the apps, with "Something stopped working?" |
| **Overview** | How protected am I? | Three cards: Protection (ring and the devices that aren't fully protected), Latest rule change (in force on N of M devices), Last 24 hours (blocked / allowed / watched only). Desktop sidebar only; on phones it is one tap from the Apps status line. |
| **Activity** | What did Moat block or notice? | Newest first, repeats grouped into one line; each opens its decision card. |
| **Tasks** | What is running inside a protected task? | Each task with its device and status; the program chain and ids under Details. |
| **Rules** | What may connect where, and who changed it? | Current rules and their history. Learn (record an app, review) and Rule packs live here as sub-views. |
| **Devices** / **This computer** | Is each device working, and what can it really do? | Each device with its coverage chip and when it last checked in. Coverage & recovery, What changed? and Diagnostics live here as sub-views. |

Navigation: six items on desktop (Apps, Overview, Activity, Tasks, Rules, Devices), five tabs on phones (no
Overview). macOS has the same jobs with six sidebar items (Apps, Activity, Tasks, Rules, Devices, Coverage &
recovery). With one device, "Devices" reads "This computer" ("Computer" in the phone tab bar).

**The decision card** ("Should I allow this?"): one sentence ("Blocked *app* from connecting", device, when, how
often), two buttons (*Allow once for this task*, *Keep blocking*) and one line of fine print saying exactly what
happens. The exact permission an approval signs (device, task, address and port, until when) is always visible once
you choose Allow once; hostnames, rule versions, signer and key ids are under Technical details.

## Components

One set, the same rules on web (`web/src/components/ui.tsx`) and macOS (`MoatUI/Components.swift`). Screens compose
these; they do not invent their own.

* **Card** (macOS `Card`): an opaque surface with a hairline border. Optional header: a title plus at most one quiet
  action (a link) or chip. **One primary action per card.**
* **SectionHeader** (macOS `SectionTitle`): one title, at most one trailing link or chip. No subtitles stacked under it.
* **Stat**: a label and a figure. Used only where a number answers the view's question; never decorative.
* **StatusChip** (macOS `Pill`): icon + label, always, from the shared vocabulary (`brand/vocabulary.json`). Neutral
  chips (counts, ids) may omit the icon. Status is never colour alone.
* **ListRow** (macOS `ListRowView`): leading icon, title, **one** sub line, trailing chip or figure. A row that opens
  something shows a chevron.
* **Banner** (macOS `NoticeBanner`): an announcement or warning across a view or card ("Sample data", "Not current",
  a device that isn't fully protected). **Coverage and safety warnings are always banners or chips and never go
  behind a disclosure**; only their exact technical reason can.
* **EmptyState**: what the view will show, and the next step when there is one. Never a placeholder chart.
* **Button hierarchy**: *primary* (one per card, solid `accent-strong`), *secondary* (the alternative, bordered),
  *quiet* (everything else, text only), *danger* (lockdown and other destructive actions, always confirmed). Labels
  say what happens ("Approve exactly this", "Keep blocking"), never "OK" or "Submit". At least 44 px tall.
* **Details** (macOS `TechnicalDetails`): the disclosure for secondary and technical detail: hostnames, ports, hashes,
  rule versions, signer, key and task ids, file paths. Closed by default. Never for a warning about coverage or safety.
* **Fine**: one or two short sentences under an action saying exactly what will happen.

## Words

Moat's own words in headings, labels, buttons, chips, banners and explanations are plain. A technical term may appear
only under Details, on a technical page (Diagnostics), in a monospace identifier, or in data a device reported.
`web/src/copy.test.tsx` renders every screen and fails if a word from the jargon list in `brand/vocabulary.json`
appears anywhere else, and checks that the macOS status labels use the same vocabulary.

Glossary (what we say, what we don't, what it means):

| Say | Not | Means |
|---|---|---|
| rule | policy, policy revision | What may connect where. Every change to your rules gets a version number, shown under Details. |
| device, this device, this computer | endpoint | A computer, phone or TV that Moat watches or protects. |
| checked just now / checked 5 min ago | evidence age | When the device last reported. Older than 10 minutes, Moat says it can't confirm. |
| connection | flow, verdict | One attempt by an app to reach a server. |
| app | executable, process, identity | An exact program, recognised by its file and its signature, never by its name alone. File path and signer are under Details. |
| task | session, protected session | Something you start through Moat, such as a coding agent, that runs inside a boundary with its own rules. |
| watched only | observed, monitoring | Moat recorded the connection but did not check it against a rule. |
| web filter | resolver, DNS | Your home's ad or DNS blocker (Pi-hole or AdGuard Home). For phones and TVs it is the only view Moat has. |
| lockdown | isolation | An emergency switch that blocks new connections until you turn it off. |
| record an app | capture | Watch one app do one job for a while, so you can decide what to allow. |
| review | candidate, permission diff | What an app tried to reach while you recorded it. Nothing is allowed until you tick it. |
| approved list | baseline | The places you allowed for one app after a review. It never changes; new activity starts a new review. |
| new since approval | drift | Places an app started reaching after you approved its list. |
| rule packs | workflow packs | Ready-made rules for common work. Nothing is turned on until you choose. |
| controller | server, backend | The Moat hub that keeps your rules and collects reports. Devices keep working without it. |
| owner key | signing key | The key only you hold. Changes that allow more need it. |
| approval key | delegated issuer | A narrow key for this phone or browser that can only approve what your owner key allows it to. |
| gap | telemetry gap | A stretch of time where reports were lost, so activity then is incomplete. |

Status words (coverage): Tasks protected, Protected, Watching only, Web filter only, Partly protected, Needs you at
the device, Undo didn't finish, Locked down, Can't confirm. Support: Works, Partly works, Not proven yet, Not
available. Each has a one-line meaning in `brand/vocabulary.json` that the UI shows next to it.

Honesty wording is not softened by plain language: "Not proven yet", "Can't confirm", "Waiting for the device to
confirm" and "Sample data" stay visible and mean exactly what they did.

## Honesty rules for visuals

* A chart draws only fields that already exist in the snapshot or the macOS model: hourly flow rollups, device
  `last_seen` evidence, revision receipts, incidents, app counts, flow records, capability rows. If nothing real
  backs a visual, it is left out.
* An empty series shows an empty state ("No flow history yet"), never a placeholder chart.
* In demo mode every chart card carries a "Sample data" tag in addition to the global banner. Screenshots in
  `docs/screenshots` are CI captures on demo data, not real devices.
* Freshness, Unverified / Degraded / Not confirmed labels, stale refusal and the read-only viewer are unchanged by the
  redesign; the visuals only restyle them.

## Accessibility

* WCAG AA contrast in both themes, checked by axe-core on every route in CI (`web/scripts/screenshots.mjs`) and by
  `tokens.test.ts` for the palette.
* Visible 2 px focus outlines with offset; hit targets of at least 44 px (tabs, nav rows, buttons, icon buttons).
* Appearance follows `prefers-color-scheme` until the owner uses the toggle; the choice then persists.
* No translucency anywhere in Moat's own surfaces, so Reduce Transparency needs no fallback. Reduce Motion removes
  animation and transitions. Increased contrast strengthens borders and secondary text. Forced colours keep borders.
* Charts carry text alternatives (`role="img"` with a label, or table semantics for the heat grid) and every chart's
  meaning is spelled out in a legend.
