#!/usr/bin/env bash
# Fill the cask template with a released version and checksum: scripts/render-cask.sh 0.1.0 <sha256>
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: $0 <version> <sha256>" >&2; exit 2; }
[[ "$2" =~ ^[0-9a-f]{64}$ ]] || { echo "sha256 must be 64 hex chars" >&2; exit 2; }
here="$(cd "$(dirname "$0")/.." && pwd)"
sed -e "s/@VERSION@/$1/g" -e "s/@SHA256@/$2/g" "$here/Casks/moat.rb.template"
