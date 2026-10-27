#!/usr/bin/env bash
# CycloneDX SBOMs for the release (MASTER_ROADMAP §15.4, §17.3).
#
#   release/sbom.sh <out-dir> [rust-target]     # needs cargo-cyclonedx on PATH (as `cargo cyclonedx`), npm >= 10
#
# Rust: one SBOM per workspace crate (moat-core, moatctl, moat-ffi, moatd), all transitive dependencies, for the
# release target (default x86_64-unknown-linux-gnu), CycloneDX 1.5 JSON.
# npm: one SBOM per workspace package (controller, web) from package-lock.json, dev dependencies included (the web
# bundle is built with them), CycloneDX 1.5 JSON.
# release/sbom-check.py then proves every locked dependency appears in an SBOM.
set -euo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
TARGET=${2:-x86_64-unknown-linux-gnu}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}

cargo cyclonedx --format json --spec-version 1.5 --all --target "$TARGET" -q
for f in $(find core linux -name '*.cdx.json' -not -path '*/target/*'); do
  mv "$f" "$OUT/moat-rust-$(basename "$f")"
done

# npm sbom needs a version on the root package; set it in a scratch copy, never in the tree.
VER=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
SCRATCH=$(mktemp -d)
cp package.json package-lock.json "$SCRATCH/"
for w in controller web; do mkdir -p "$SCRATCH/$w"; cp "$w/package.json" "$SCRATCH/$w/"; done
(cd "$SCRATCH" && npm pkg set "version=$VER" name=moat)
for w in controller web; do
  (cd "$SCRATCH" && npm sbom --sbom-format cyclonedx --sbom-type application --package-lock-only -w "$w") > "$OUT/moat-npm-$w.cdx.json"
done
rm -rf "$SCRATCH"
ls -1 "$OUT"/*.cdx.json
