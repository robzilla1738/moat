#!/usr/bin/env bash
# Build the Rust moat-core C ABI (core/moat-ffi) as a static library for the macOS app and extension.
#   scripts/build-ffi.sh             native arch, release
#   scripts/build-ffi.sh --universal arm64 + x86_64 (lipo), for releases
# Output: macos/build/ffi/libmoat_ffi.a (+ header check against the SwiftPM copy).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/.." && pwd)"
out="$here/build/ffi"
mkdir -p "$out"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"

if ! cmp -s "$root/core/moat-ffi/include/moat_ffi.h" "$here/MoatKit/Sources/CMoatFFI/moat_ffi.h"; then
  echo "error: macos/MoatKit/Sources/CMoatFFI/moat_ffi.h differs from core/moat-ffi/include/moat_ffi.h" >&2
  exit 1
fi

if [[ "${1:-}" == "--universal" ]]; then
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  for t in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --manifest-path "$root/Cargo.toml" -p moat-ffi --release --target "$t"
  done
  lipo -create -output "$out/libmoat_ffi.a" \
    "$target_dir/aarch64-apple-darwin/release/libmoat_ffi.a" \
    "$target_dir/x86_64-apple-darwin/release/libmoat_ffi.a"
else
  cargo build --manifest-path "$root/Cargo.toml" -p moat-ffi --release
  cp "$target_dir/release/libmoat_ffi.a" "$out/libmoat_ffi.a"
fi
lipo -info "$out/libmoat_ffi.a" 2>/dev/null || true
echo "built $out/libmoat_ffi.a"
