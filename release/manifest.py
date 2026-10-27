#!/usr/bin/env python3
"""Release manifest: which capabilities were tested on which versions (MASTER_ROADMAP §15.4, §17.2).

Generated from docs/claim-ledger.json, never written by hand. For every claim it records the disposition, the
evidence level, the environment and the exact commit and CI run that produced the last result, and whether that
result was produced at the commit being released. A binary does not inherit a claim because it carries the same
version label: a claim tested at another commit is listed as `tested_elsewhere`, not as covering this build.

    python3 release/manifest.py --commit <sha> --out-dir dist/

Writes release-manifest.json and release-manifest.md. Exits non-zero if the ledger breaks a release rule
(a supported claim without installed or real-workflow evidence, a supported claim with an open defect, a
supported claim whose result was not produced at a commit this release contains).
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def workspace_version():
    txt = open(os.path.join(ROOT, "Cargo.toml")).read()
    m = re.search(r'\[workspace\.package\][^\[]*?version\s*=\s*"([^"]+)"', txt, re.S)
    return m.group(1) if m else "unknown"


def npm_versions():
    out = {}
    for d in ("controller", "web"):
        p = os.path.join(ROOT, d, "package.json")
        if os.path.exists(p):
            j = json.load(open(p))
            out[j.get("name", d)] = j.get("version", "unversioned")
    return out


def is_ancestor(short, commit):
    """True if `short` is `commit` or an ancestor of it (needs a full clone; None when git cannot tell)."""
    if not short:
        return False
    try:
        r = subprocess.run(["git", "-C", ROOT, "merge-base", "--is-ancestor", short, commit], capture_output=True)
    except FileNotFoundError:
        return None
    if r.returncode in (0, 1):
        return r.returncode == 0
    return None


def build(commit):
    ledger = json.load(open(os.path.join(ROOT, "docs", "claim-ledger.json")))
    open_defects = {d["id"] for d in ledger.get("defects", []) if d.get("status") == "open"}
    problems, rows = [], []
    for c in ledger["claims"]:
        lr = c.get("last_result", {})
        tested = lr.get("commit")
        if lr.get("result") == "not_run" or not tested:
            relation = "not_run"
        elif len(tested) >= 7 and commit.startswith(tested):
            relation = "this_commit"
        else:
            anc = is_ancestor(tested, commit)
            relation = "tested_earlier_commit" if anc else ("tested_elsewhere" if anc is False else "unknown_relation")
        row = {
            "id": c["id"],
            "capability": c["capability"],
            "backend": c["backend"],
            "disposition": c["disposition"],
            "evidence_level": c["evidence_level"],
            "environment": c["environment"],
            "environment_description": ledger["environments"].get(c["environment"], ""),
            "last_result": lr.get("result"),
            "tested_commit": tested,
            "tested_run": lr.get("run"),
            "tested_date": lr.get("date"),
            "tested_relation_to_release": relation,
            "open_defects": [d for d in c.get("open_defects", []) if d in open_defects],
            "limits": c["limits"],
        }
        rows.append(row)
        if c["disposition"] == "supported_installed":
            if c["evidence_level"] not in ("installed", "real_workflow"):
                problems.append(f"{c['id']}: supported without installed/real-workflow evidence")
            if row["open_defects"]:
                problems.append(f"{c['id']}: supported with open defects {row['open_defects']}")
            if relation not in ("this_commit", "tested_earlier_commit"):
                problems.append(f"{c['id']}: supported but its result ({tested}) is not from a commit in this release")
    counts = {}
    for r in rows:
        counts[r["disposition"]] = counts.get(r["disposition"], 0) + 1
    manifest = {
        "schema": "moat.release_manifest.v1",
        "release_commit": commit,
        "workspace_version": workspace_version(),
        "npm_packages": npm_versions(),
        "ledger_schema": ledger["schema"],
        "ledger_updated": ledger.get("updated"),
        "statement": "Claims cover only the backend, environment and commit named in each row. A row whose "
        "tested_relation_to_release is not this_commit was not re-run on this build. Nothing is supported unless its "
        "disposition is supported_installed.",
        "disposition_counts": counts,
        "claims": rows,
        "open_defects": sorted(open_defects),
    }
    return manifest, problems


def markdown(m):
    out = [
        f"# Moat release manifest — {m['release_commit'][:12]}",
        "",
        f"Workspace version `{m['workspace_version']}`; generated from the claim ledger (updated {m['ledger_updated']}).",
        "",
        m["statement"],
        "",
        "Dispositions: " + ", ".join(f"`{k}` {v}" for k, v in sorted(m["disposition_counts"].items())),
        "",
        "| Claim | Disposition | Evidence | Environment | Result | Tested at | Relation to this build |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in m["claims"]:
        out.append(
            f"| `{r['id']}` | {r['disposition']} | {r['evidence_level']} | {r['environment']} | {r['last_result']} | "
            f"{r['tested_commit'] or '—'} ({r['tested_run'] or 'no run'}) | {r['tested_relation_to_release']} |"
        )
    out += ["", "Open defects: " + (", ".join(f"`{d}`" for d in m["open_defects"]) or "none"), ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA") or "HEAD")
    ap.add_argument("--out-dir", default="dist")
    a = ap.parse_args()
    commit = a.commit
    if commit == "HEAD":
        commit = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    m, problems = build(commit)
    os.makedirs(a.out_dir, exist_ok=True)
    json.dump(m, open(os.path.join(a.out_dir, "release-manifest.json"), "w"), indent=2)
    open(os.path.join(a.out_dir, "release-manifest.md"), "w").write(markdown(m))
    print(json.dumps(m["disposition_counts"]), f"{len(m['claims'])} claims", file=sys.stderr)
    for p in problems:
        print("RELEASE RULE BROKEN:", p, file=sys.stderr)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
