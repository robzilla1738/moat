#!/usr/bin/env python3
"""Dependency licence report and copyleft gate (MASTER_ROADMAP §15.4, §17.3).

    python3 release/license-gate.py --cargo cargo-licenses.json --npm npm-licenses.json --out license-report.md

Inputs: `cargo deny list -f json -l crate` and `license-checker --json` output. Writes one Markdown report and
exits non-zero if any dependency of the Apache-2.0 components is GPL, AGPL or LGPL with no permissive alternative,
or carries no licence at all. The Rust side is also gated by `cargo deny check licenses` (deny.toml allowlist, which
evaluates SPDX expressions exactly); this script is the second, explicit copyleft check and the npm gate.
"""
import argparse
import json
import re
import sys

COPYLEFT = re.compile(r"\b(A?GPL|LGPL)", re.I)
# Our own workspace packages (private, Apache-2.0 by the root LICENSE).
OWN = re.compile(r"^(moat|@moat/|moat-core|moatctl|moat-ffi|moatd)\b")


def alternatives(expr):
    """Split an SPDX-like expression into OR alternatives (each a set of AND-ed terms)."""
    e = expr.strip()
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1].strip()
    return [alt.strip(" ()") for alt in re.split(r"\s+OR\s+|\s*/\s*", e, flags=re.I)]


def verdict(expr):
    if not expr or expr.upper() in ("UNKNOWN", "UNLICENSED", "NONE"):
        return "no_licence"
    alts = alternatives(expr)
    if any(not COPYLEFT.search(a) for a in alts):
        return "ok"
    return "copyleft"


def self_test():
    """Negative controls: the gate must fail these, so a broken parser cannot pass everything."""
    cases = {
        "MIT": "ok", "Apache-2.0 OR MIT": "ok", "(MIT OR GPL-3.0-or-later)": "ok", "MIT/Apache-2.0": "ok",
        "GPL-3.0": "copyleft", "GPL-2.0-only": "copyleft", "AGPL-3.0-or-later": "copyleft", "LGPL-2.1": "copyleft",
        "(GPL-2.0 OR LGPL-3.0)": "copyleft", "GPL-3.0 AND MIT": "copyleft", "UNKNOWN": "no_licence", "": "no_licence",
    }
    for expr, want in cases.items():
        got = verdict(expr)
        assert got == want, f"verdict({expr!r}) = {got}, want {want}"
    print(f"license-gate self-test: {len(cases)} cases ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser()
    ap.add_argument("--cargo", required=True)
    ap.add_argument("--npm", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rows, bad = [], []

    for key, v in json.load(open(a.cargo)).items():
        name, ver = key.split(" ")[:2]
        lic = v.get("licenses") or []
        # cargo-deny's list splits an expression into its licences; it cannot say AND vs OR. Treat a crate as copyleft
        # only when every licence it names is copyleft; `cargo deny check licenses` evaluates the exact expression.
        expr = " OR ".join(lic)
        vd = verdict(expr) if not OWN.match(name) else "own"
        rows.append(("cargo", name, ver, " / ".join(lic) or "NONE", vd))

    for key, v in json.load(open(a.npm)).items():
        name, _, ver = key.rpartition("@")
        lic = v.get("licenses")
        expr = " OR ".join(lic) if isinstance(lic, list) else (lic or "")
        vd = "own" if OWN.match(name) else verdict(expr.replace("*", ""))
        rows.append(("npm", name, ver, expr or "NONE", vd))

    for r in rows:
        if r[4] in ("copyleft", "no_licence"):
            bad.append(r)
    with open(a.out, "w") as f:
        f.write("# Dependency licence report\n\n")
        f.write(f"{sum(1 for r in rows if r[0]=='cargo')} Rust crates, {sum(1 for r in rows if r[0]=='npm')} npm packages. ")
        f.write("Gate: no GPL/AGPL/LGPL-only and no unlicensed dependency in the Apache-2.0 components.\n\n")
        f.write(f"**Result: {'FAIL' if bad else 'pass'}**\n\n")
        if bad:
            f.write("## Failing\n\n| Ecosystem | Package | Version | Licence | Verdict |\n| --- | --- | --- | --- | --- |\n")
            for r in bad:
                f.write("| " + " | ".join(r) + " |\n")
            f.write("\n")
        f.write("## All dependencies\n\n| Ecosystem | Package | Version | Licence | Verdict |\n| --- | --- | --- | --- | --- |\n")
        for r in sorted(rows):
            f.write("| " + " | ".join(r) + " |\n")
    counts = {}
    for r in rows:
        counts[r[3]] = counts.get(r[3], 0) + 1
    print(json.dumps(dict(sorted(counts.items(), key=lambda kv: -kv[1]))))
    for r in bad:
        print("LICENCE GATE:", *r, file=sys.stderr)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
