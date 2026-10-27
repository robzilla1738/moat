# Learning, baselines and workflow packs (W14)

Learning produces a **proposal, never trust** (MASTER_ROADMAP §9.4). Code: `controller/src/learning.ts`,
`controller/src/packs.ts`, packs in `packs/workflows/`. Tests: `controller/test/learning.test.ts`.

| Step | What happens | What never happens |
| --- | --- | --- |
| Capture (`POST /v1/learning/captures`) | Bound to one device, one executable identity (path + signer), one named workflow, one network context, at most 8 hours and 20 000 records. Reads the flow store only. | Existing rules are not relaxed; denies stay enforced during capture. |
| Candidate | Exact destinations seen, each `proposed`, with occurrence counts. `complete` only with no gaps, no pending holes and no unknown identity; otherwise the reasons are listed. | Repetition or volume never accepts an entry. Nothing is accepted by default. |
| Review (`/candidates/:id/approve`) | The owner selects entries one by one; an incomplete candidate needs an explicit acknowledgement. The approved baseline is immutable (DB triggers). | A baseline is never edited in place. |
| Enforce (`/baselines/:id/propose`) | Becomes an ordinary policy proposal (exact app, exact hosts) approved through the owner-key path. | No grant or rule is installed without the owner key. |
| Drift (`/baselines/:id/drift`) | New activity creates a **new** candidate; same-family identity changes (e.g. a new signer or path after an app update) are listed, not inherited; entries unused for 30 days are proposed for removal with a seasonal-use caveat. | A weak name match does not carry permissions to a changed app. |
| Import (`/learning/import`) | Keeps source and compatibility assumptions; wildcards or missing assumptions are refused. | — |

Acknowledging an incident means "seen"; muting means "no notifications until …". Neither allows anything.

## Workflow packs

Three maintained packs: coding, home services, local inference. Each module carries rationale, required
capabilities, version, known breakage, provenance and a test recipe. Enabling a module is an owner-authorized
broadening proposal (`POST /v1/packs/propose`). Pack count is not a success metric.

## Not yet proven

Claim `learning.reviewed-baselines`: `implemented_unproven`, component evidence ([STATUS](STATUS.md)).
Learning runs on recorded flows from real endpoints only when those endpoints send them; recorded-flow rehearsal is an
estimate. No capture from a real device has been reviewed, and alert volume and learning quality are unmeasured.

## Review surfaces (#61)

Web (`web/src/screens/Learning.tsx`) and macOS (`macos/MoatKit/Sources/MoatUI/LearningScreens.swift`,
`MoatKit/Learning.swift`) show captures, candidate review with a permission diff, gaps, unknown identity and
connections that were only ever refused, owner-only accept, the drift queue and a pack browser with per-device
unsupported cells. On the web, enforcing a baseline prepares an unsigned proposal that waits for an owner-key
authorization made off the page (`moat-controller owner-authorize`). On the Mac, accepting needs the Keychain owner key
behind user presence and is refused without it. Tests: `controller/test/learning.test.ts`, `web/src/learning.test.tsx`,
the live e2e (`web/e2e/live.e2e.ts`) and `macos/MoatKit/Tests/MoatKitTests/LearningTests.swift`. Screenshots:
`docs/screenshots/*learning*`, `*packs*`, `macos-candidate-light.png`.
