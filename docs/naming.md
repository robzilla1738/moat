# Naming: the "Moat" collision (MASTER_ROADMAP §17.5)

**Status:** open; working name kept while engineering continues. Decision belongs to Robert.
**This page is a factual note, not a legal opinion.** It records what other projects publicly use the name, where
Moat's own names could clash in practice (package managers, executables, paths), and the options. No contact with
any other maintainer has been made. Checked 2026-10-27; re-check before any public installation path is announced.

## Other projects using the name (as publicly described by them)

| Project | What it is | Public names it uses | Source |
| --- | --- | --- | --- |
| Moat by Major Context (`majorcontext/moat`) | Go CLI that runs AI agents in containers with credential injection and observability | Homebrew `brew tap majorcontext/tap && brew install moat`; executable `moat`; data in `~/.moat/`; project file `moat.yaml` | https://majorcontext.com/moat/getting-started/installation/ · https://github.com/majorcontext/moat |
| OpenMoat (`crocodile-labs/openmoat`) | Local guard (hooks, OS sandbox, proxy) for coding agents | Homebrew `crocodile-labs/tap/openmoat`; executable `openmoat` (its site says the command was `moat` in 0.7 and earlier); policy in `~/.moat/policy.yaml` | https://openmoat.dev/ |
| `nochinsky/moat` | Runs a coding agent in a disposable Linux sandbox | npm package `moat-sandbox`; command `moat` | https://github.com/nochinsky/moat |

Several of these are in the same space as this project (security for AI coding agents), which is what makes the
collision practical rather than incidental.

## Where this project's names would clash

| This project uses | Clash |
| --- | --- |
| Homebrew cask `moat` (`macos/Casks/moat.rb.template`, planned private tap `robzilla1738/homebrew-moat`) | A cask and a formula can share a token in different taps, but `brew install moat` is ambiguous for users who have tapped Major Context's tap; docs and search results would mix the two. |
| Product name "Moat" in the Mac app, cask `name` and README | Same word, same audience (agent security). |
| Executables `moatd`, `moatctl`, `moat-launch` | No direct clash found with these exact names. There is no `moat` executable in this repo today; adding one would clash with Major Context's CLI on `PATH`. |
| Paths `/var/lib/moat`, `/run/moat/control.sock` | System paths; the other projects listed use `~/.moat/` in the user's home. No overlap found, but a future per-user config should not use `~/.moat`. |
| Bundle id `com.coursondigital.moat` | Reverse-DNS under Courson Digital; no clash. |
| GitHub repo `robzilla1738/moat`, crates `moat-core`, `moatctl`, `moat-ffi`, `moatd` (all `publish = false`) | Not published to crates.io; a crates.io name check is needed only if publishing is ever planned. |

## Options

1. **Keep "Moat" for the product, make every install-facing namespace distinctive.** Cask/tap and package names
   with a qualifier (for example a `-firewall` suffix or a Courson Digital tap), never ship an executable named
   `moat`, keep `moatd`/`moatctl`. Cheapest; the brand stays ambiguous in search and conversation.
2. **Qualified brand** ("Moat Firewall", "Courson Moat" or similar) across app name, cask, docs. Moderate cost:
   strings, cask, bundle display name, docs; identifiers can stay.
3. **Rename before the first public release.** Highest one-time cost (bundle ids, paths, crate and binary names,
   docs, screenshots, CI) but lowest long-term confusion. The cost grows with every release and every installed
   machine, because paths like `/var/lib/moat` and bundle ids need a migration once users exist.
4. **Defer** until a public installation path is about to be announced. Engineering is unaffected; this page lists
   what to change.

What does not depend on the choice: no executable named `moat` should be added, and no per-user `~/.moat` path
should be introduced, while the question is open. Neither exists today.

## What a decision needs

* Robert's choice among the options above (and, if renaming, the new name).
* A search of the new name across Homebrew (core and popular taps), crates.io, npm, PyPI, GitHub and the Mac App
  Store. Any trademark question is for a qualified adviser; this repository makes no legal claim either way.
