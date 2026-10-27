// An independent JavaScript consumer of the W01 fixtures (no dependencies, no Rust).
//
// It proves the canonicalization rules in contracts/README.md are implementable outside Rust: every valid fixture
// canonicalizes to the digest recorded in fixtures/manifest.json, and every schema-layer invalid fixture is rejected
// by the JSON schema subset plus the canonical value domain. Semantic-layer rejects need the semantic checks
// described in the README; those are exercised by the Rust suite and must be implemented by each consumer that acts
// on the object (Lane B: controller/web/macOS).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");
const manifest = JSON.parse(read("fixtures/manifest.json"));

/** Reject number tokens that are not plain non-negative integers (JSON.parse would silently turn 443.0 into 443). */
function numberTokensAreIntegers(text) {
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (c === "\\") i++;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i;
      while (j < text.length && /[0-9eE+\-.]/.test(text[j])) j++;
      const tok = text.slice(i, j);
      if (!/^(0|[1-9][0-9]*)$/.test(tok)) return false;
      i = j - 1;
    }
  }
  return true;
}

function domainErrors(v, path, out) {
  if (v === null) out.push(`${path}: null`);
  else if (typeof v === "number") { if (!Number.isSafeInteger(v) || v < 0) out.push(`${path}: number domain`); }
  else if (Array.isArray(v)) v.forEach((x, i) => domainErrors(x, `${path}[${i}]`, out));
  else if (typeof v === "object") for (const [k, x] of Object.entries(v)) {
    if (!/^[a-z0-9_]+$/.test(k)) out.push(`${path}.${k}: key`);
    domainErrors(x, `${path}.${k}`, out);
  }
}

/** Canonical JSON: keys sorted by code point, no whitespace. */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}
const digest = (s) => "sha256:" + createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

function schemaErrors(schema, v, path, out) {
  if (schema.$ref) return schemaErrors(JSON.parse(read(`schemas/${schema.$ref}`)), v, path, out);
  if ("const" in schema) { if (canonical(schema.const) !== canonical(v)) out.push(`${path}: const`); return; }
  if (schema.enum && !schema.enum.some((e) => canonical(e) === canonical(v))) out.push(`${path}: enum`);
  switch (schema.type) {
    case "object": {
      if (!v || typeof v !== "object" || Array.isArray(v)) { out.push(`${path}: object`); return; }
      for (const r of schema.required ?? []) if (!(r in v)) out.push(`${path}.${r}: required`);
      for (const [k, x] of Object.entries(v)) {
        const ps = schema.properties?.[k];
        if (ps) schemaErrors(ps, x, `${path}.${k}`, out);
        else if (schema.additionalProperties === false) out.push(`${path}.${k}: unknown field`);
      }
      break;
    }
    case "array":
      if (!Array.isArray(v)) { out.push(`${path}: array`); return; }
      if (schema.items) v.forEach((x, i) => schemaErrors(schema.items, x, `${path}[${i}]`, out));
      break;
    case "string": if (typeof v !== "string") out.push(`${path}: string`); break;
    case "boolean": if (typeof v !== "boolean") out.push(`${path}: boolean`); break;
    case "integer":
      if (!Number.isSafeInteger(v) || v < 0) out.push(`${path}: integer`);
      else if (schema.maximum !== undefined && v > schema.maximum) out.push(`${path}: maximum`);
      break;
  }
}
const schemaFor = (id) => JSON.parse(read(`schemas/${id}.schema.json`));

for (const f of manifest.fixtures) {
  test(`${f.expect} ${f.file}`, () => {
    const text = read(`fixtures/${f.file}`);
    const v = JSON.parse(text);
    const errs = [];
    if (!numberTokensAreIntegers(text)) errs.push("$: non-integer number token");
    domainErrors(v, "$", errs);
    if (v?.schema !== f.schema) errs.push("$.schema: unsupported schema id");
    schemaErrors(schemaFor(f.schema), v, "$", errs);
    if (f.expect === "accept") {
      assert.deepEqual(errs, []);
      assert.equal(digest(canonical(v)), f.canonical_sha256, "canonical digest matches the Rust implementation");
    } else if (f.layer === "schema") {
      assert.notDeepEqual(errs, [], `schema-layer reject must fail structurally: ${f.reason}`);
    } else {
      assert.deepEqual(errs, [], "semantic-layer rejects are structurally valid; consumers need the semantic checks");
    }
  });
}

test("receipt freshness is computed by the consumer, not the sender's label", () => {
  for (const f of manifest.fixtures.filter((x) => x.freshness)) {
    const r = JSON.parse(read(`fixtures/${f.file}`));
    const now = Date.parse(f.freshness.now);
    const at = Date.parse(r.observed_at);
    const unc = r.clock.uncertainty_ms;
    let got;
    if (r.clock.source === "unsynchronized" || at - unc > now) got = "unknown";
    else got = now - (at - unc) <= f.freshness.max_age_seconds * 1000 ? "fresh" : "stale";
    assert.equal(got, f.freshness.expect, f.file);
  }
});
