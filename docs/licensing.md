# Licensing

Moat is **Apache-2.0** (see `LICENSE`), aligned with Digital Kingdom.

## No GPL code is copied

LuLu and OpenSnitch are **GPLv3**. Moat does not contain, translate, or adapt their source. They were studied at the
level of public documentation and architecture (what a content filter or a Netfilter-based agent can observe), and
every line here is an independent implementation. Contributors must not paste or port code from GPL projects into
this repository; a PR that does will be rejected.

* An **OpenSnitch adapter** (talking to an unmodified OpenSnitch daemon over its documented protocol, distributed
  separately) was evaluated in [platforms/opensnitch-adapter-feasibility.md](platforms/opensnitch-adapter-feasibility.md).
  A separate-process architecture is useful engineering separation, **not an automatic legal exemption**; any
  distributed combination needs a focused license review first.
* Apache-2.0 for Moat does not relicense anything copied from elsewhere. Provenance of adapted code is recorded at
  the top of the file.

## Adapted from Digital Kingdom (Apache-2.0)

Concepts and small portions adapted from Digital Kingdom (`robzilla1738/Digital-Kingdom` @ `e0452c8`, Apache-2.0)
are marked in source, e.g. `core/moat-core/src/authority.rs` (producer authority, from
`packages/detections/src/capabilities.ts`). Same license, attribution kept.

## Third-party dependencies

Rust crates and npm packages are pulled through `Cargo.lock` / `package-lock.json` under their own permissive
licenses (MIT / Apache-2.0 / BSD / ISC). CI generates the dependency licence report on every push
(`release-engineering` workflow, artifact `license-report`): `cargo deny check licenses` against the allowlist in
`deny.toml` and `license-checker` for npm, then `release/license-gate.py`, which **fails on GPL, AGPL or LGPL
without a permissive alternative, or on a missing licence**, in any dependency of the Apache-2.0 components. The
report ships with each release. A full SBOM is not generated yet.

A future BPF program for Linux app enforcement would need a GPL-compatible licence string to use GPL-only kernel
helpers; it would be a separate artifact under `linux/bpf/`, not linked into the Apache crates, and needs a licensing
decision before it ships ([W10 loader decision](decisions/W10-increment-3-loader.md)).

## Commercial options

Open core, support subscriptions or a paid team control plane all remain possible because the core is Apache-2.0
and no copyleft code is linked. Get a focused license review before shipping any proprietary combination.
