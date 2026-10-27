/**
 * One palette, three consumers. brand/design-tokens.json is the source; web/src/tokens.css and the macOS colour sets
 * are generated from it (web/scripts/brand.mjs), and macos/MoatKit/Sources/MoatUI/Theme.swift is kept in sync by
 * hand. This test fails when any of them drifts.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(__dirname, "../..");
const tokens = JSON.parse(readFileSync(resolve(root, "brand/design-tokens.json"), "utf8")) as { color: Record<"light" | "dark", Record<string, string>> };
const css = readFileSync(resolve(root, "web/src/tokens.css"), "utf8");
const swift = readFileSync(resolve(root, "macos/MoatKit/Sources/MoatUI/Theme.swift"), "utf8");

const swiftName = (k: string) => k.replace(/-(\w)/g, (_, c: string) => c.toUpperCase()).replace(/-/g, "");

function swiftPalette(which: "light" | "dark"): Record<string, string> {
  const start = swift.indexOf(`public static let ${which} = Palette(`);
  const body = swift.slice(start, swift.indexOf("))", start) + 2);
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/(\w+): Color\(hex: 0x([0-9A-Fa-f]{6})\)/g)) out[m[1]!] = `#${m[2]!.toUpperCase()}`;
  return out;
}

describe("design tokens", () => {
  for (const scheme of ["light", "dark"] as const) {
    it(`tokens.css matches design-tokens.json (${scheme})`, () => {
      const block = css.slice(css.indexOf(scheme === "light" ? ':root,\n[data-theme="light"]' : '[data-theme="dark"]'));
      for (const [k, v] of Object.entries(tokens.color[scheme])) expect(block).toContain(`--${k}: ${v};`);
    });
    it(`Theme.swift matches design-tokens.json (${scheme})`, () => {
      const p = swiftPalette(scheme);
      for (const [k, v] of Object.entries(tokens.color[scheme])) expect(p[swiftName(k).replace(/^chart(\d)$/, "chart$1")], k).toBe(v.toUpperCase());
    });
  }
  it("light text colours meet WCAG AA on white", () => {
    const lum = (hex: string) => {
      const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
      return 0.2126 * c[0]! + 0.7152 * c[1]! + 0.0722 * c[2]!;
    };
    const ratio = (a: string, b: string) => {
      const [x, y] = [lum(a), lum(b)].sort((m, n) => n - m);
      return (x! + 0.05) / (y! + 0.05);
    };
    const L = tokens.color.light;
    for (const k of ["text", "text-2", "muted", "accent", "green", "red", "amber", "blue", "violet", "teal"]) expect(ratio(L[k]!, L.surface!), k).toBeGreaterThanOrEqual(4.5);
    const D = tokens.color.dark;
    for (const k of ["text", "text-2", "muted", "accent", "green", "red", "amber", "blue", "violet", "teal"]) expect(ratio(D[k]!, D.surface!), k).toBeGreaterThanOrEqual(4.5);
  });
});
