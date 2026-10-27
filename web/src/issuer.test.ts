import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson, contractDigest } from "./data/issuer";

const root = join(__dirname, "../../contracts/fixtures");
const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")) as { fixtures: { file: string; schema: string; expect: string; canonical_sha256?: string }[] };

describe("browser approval digest", () => {
  it("matches the Rust canonical digest of every valid moat.grant.v1 fixture (what the signer checks)", () => {
    const grants = manifest.fixtures.filter((f) => f.schema === "moat.grant.v1" && f.expect === "accept");
    expect(grants.length).toBeGreaterThan(0);
    for (const f of grants) expect(contractDigest(JSON.parse(readFileSync(join(root, f.file), "utf8")))).toBe(f.canonical_sha256);
  });
  it("is order-independent and changes with any scope field", () => {
    const g = JSON.parse(readFileSync(join(root, "valid/grant-app-on-device.json"), "utf8")) as Record<string, unknown>;
    const reordered = Object.fromEntries(Object.entries(g).reverse());
    expect(canonicalJson(reordered)).toBe(canonicalJson(g));
    expect(contractDigest({ ...g, port: 8443 })).not.toBe(contractDigest(g));
  });
});
