#!/usr/bin/env python3
"""Fail if any workflow uses a third-party action by tag or branch instead of a full commit SHA (§17.3).

    python3 release/check-actions-pinned.py .github/workflows
"""
import os
import re
import sys

USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
PINNED = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
bad, n = [], 0
root = sys.argv[1] if len(sys.argv) > 1 else ".github/workflows"
for f in sorted(os.listdir(root)):
    if not f.endswith((".yml", ".yaml")):
        continue
    for i, line in enumerate(open(os.path.join(root, f)), 1):
        m = USES.match(line)
        if not m:
            continue
        ref = m.group(1).strip("'\"")
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        n += 1
        if not PINNED.match(ref):
            bad.append(f"{f}:{i}: {ref}")
for b in bad:
    print("NOT PINNED", b)
print(f"{n} action references, {len(bad)} not pinned to a commit SHA")
sys.exit(1 if bad else 0)
