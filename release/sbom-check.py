#!/usr/bin/env python3
"""SBOM gate: every locked dependency appears in a CycloneDX SBOM (MASTER_ROADMAP §15.4).

    python3 release/sbom-check.py --dir dist [--target x86_64-unknown-linux-gnu]
    python3 release/sbom-check.py --dir dist --self-test

Checks each moat-*.cdx.json is CycloneDX 1.5 JSON with a root component and components, then
proves coverage so an SBOM cannot pass vacuously:
  * Rust: every package `cargo metadata --filter-platform <target>` resolves for the workspace members through
    normal and build dependencies is present (name and version) in the union of the moat-rust-*.cdx.json files.
  * npm: every non-link package in package-lock.json is present (name and version) in the union of the
    moat-npm-*.cdx.json files.
--self-test drops one component from a copy of each SBOM set and requires the gate to fail.
"""
import argparse
import copy
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(paths):
    boms = {}
    for p in paths:
        with open(p) as f:
            boms[os.path.basename(p)] = json.load(f)
    return boms


def shape_problems(name, bom):
    out = []
    if bom.get("bomFormat") != "CycloneDX":
        out.append(f"{name}: bomFormat is not CycloneDX")
    if bom.get("specVersion") != "1.5":
        out.append(f"{name}: specVersion {bom.get('specVersion')} (want 1.5)")
    if not bom.get("metadata", {}).get("component", {}).get("name"):
        out.append(f"{name}: missing metadata.component")
    if not bom.get("components"):
        out.append(f"{name}: no components")
    return out


def present(boms):
    have = set()
    for bom in boms.values():
        root = bom.get("metadata", {}).get("component")
        stack = ([root] if root else []) + list(bom.get("components", []))
        while stack:
            c = stack.pop()
            have.add((c.get("name"), c.get("version")))
            if c.get("group"):
                have.add((f"{c['group']}/{c['name']}", c.get("version")))
            stack.extend(c.get("components", []))
    return have


def rust_expected(target):
    md = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", target], cwd=ROOT))
    pkgs = {p["id"]: p for p in md["packages"]}
    nodes = {n["id"]: n for n in md["resolve"]["nodes"]}
    seen, stack = set(), list(md["workspace_members"])
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i].get("deps", []):
            if any(k.get("kind") in (None, "build") for k in d.get("dep_kinds", [])):
                stack.append(d["pkg"])
    return {(pkgs[i]["name"], pkgs[i]["version"]) for i in seen}


def npm_expected():
    lock = json.load(open(os.path.join(ROOT, "package-lock.json")))
    out = set()
    for key, p in lock.get("packages", {}).items():
        if not key or p.get("link") or "node_modules/" not in key:
            continue
        out.add((p.get("name") or key.rsplit("node_modules/", 1)[1], p.get("version")))
    return out


def gate(rust, npm, target, rust_exp=None, npm_exp=None):
    problems = []
    if not rust:
        problems.append("no moat-rust-*.cdx.json")
    if not npm:
        problems.append("no moat-npm-*.cdx.json")
    for n, b in {**rust, **npm}.items():
        problems += shape_problems(n, b)
    rust_exp = rust_expected(target) if rust_exp is None else rust_exp
    npm_exp = npm_expected() if npm_exp is None else npm_exp
    missing_r = sorted(rust_exp - present(rust))
    missing_n = sorted(npm_exp - present(npm))
    if missing_r:
        problems.append(f"{len(missing_r)} Rust packages missing from the SBOMs: {missing_r[:10]}")
    if missing_n:
        problems.append(f"{len(missing_n)} npm packages missing from the SBOMs: {missing_n[:10]}")
    return problems, len(rust_exp), len(npm_exp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--target", default="x86_64-unknown-linux-gnu")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    rust = load(sorted(glob.glob(os.path.join(a.dir, "moat-rust-*.cdx.json"))))
    npm = load(sorted(glob.glob(os.path.join(a.dir, "moat-npm-*.cdx.json"))))
    rust_exp, npm_exp = rust_expected(a.target), npm_expected()
    problems, nr, nn = gate(rust, npm, a.target, rust_exp, npm_exp)
    if a.self_test:
        if problems:
            print("self-test needs a passing SBOM set first:", *problems, sep="\n  ")
            return 1
        failures = []
        for label, boms, other in (("rust", rust, npm), ("npm", npm, rust)):
            # Drop one locked dependency from every SBOM in the set (it may appear in several).
            victim = next(c for b in boms.values() for c in b["components"]
                          if (c.get("name"), c.get("version")) in (rust_exp if label == "rust" else npm_exp)
                          and c.get("name") != b["metadata"]["component"]["name"])
            key = (victim["name"], victim["version"])
            cut = copy.deepcopy(boms)
            for b in cut.values():
                b["components"] = [c for c in b["components"] if (c.get("name"), c.get("version")) != key]
            args = (cut, other) if label == "rust" else (other, cut)
            p, _, _ = gate(*args, a.target, rust_exp, npm_exp)
            if not any("missing" in x for x in p):
                failures.append(f"dropping {label} {key} did not fail the gate")
            else:
                print(f"negative control: dropping {label} {key[0]} {key[1]} fails the gate")
        empty = {"moat-npm-x.cdx.json": {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}}
        p, _, _ = gate(rust, empty, a.target, rust_exp, npm_exp)
        if not p:
            failures.append("an empty npm SBOM passed")
        else:
            print("negative control: an empty npm SBOM fails the gate")
        if failures:
            print(*failures, sep="\n")
            return 1
        return 0
    if problems:
        print("SBOM gate failed:", *problems, sep="\n  ")
        return 1
    print(f"SBOM gate: {len(rust)} Rust SBOMs cover {nr} resolved crates for {a.target}; "
          f"{len(npm)} npm SBOMs cover {nn} locked packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
