/**
 * The stylesheet uses only the design tokens (brand/design-tokens.json → tokens.css). A raw colour, spacing value,
 * font size, font weight or radius outside the token scales fails here, so one-off styles cannot creep back in.
 */
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const css = readFileSync(resolve(__dirname, "styles.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
const tokens = readFileSync(resolve(__dirname, "tokens.css"), "utf8");
const decls = [...css.matchAll(/([a-z-]+)\s*:\s*([^;{}]+);/g)].map((m) => ({ prop: m[1]!, value: m[2]!.trim(), line: css.slice(0, m.index).split("\n").length }));
const defined = new Set([...tokens.matchAll(/--([a-z0-9-]+):/g)].map((m) => m[1]!));

describe("styles.css uses only design tokens", () => {
  it("has no literal colours outside the two shadow tokens", () => {
    const bad = decls.filter((d) => !d.prop.startsWith("-") && /#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(|\b(white|black)\b/i.test(d.value));
    expect(bad.map((d) => `${d.line}: ${d.prop}: ${d.value}`)).toEqual([]);
    const shadowLiterals = decls.filter((d) => d.prop.startsWith("--") && /rgba?\(/.test(d.value)).map((d) => d.prop);
    expect(new Set(shadowLiterals)).toEqual(new Set(["--shadow", "--shadow-pop"]));
  });
  it("spacing (padding, margin, gap) comes from the --s-* scale", () => {
    // strip the allowed parts (spacing tokens, safe-area insets, calc, auto); only operators, parentheses and 0 may remain
    const ok = (v: string) => /^[\s()+*\-0]*(1[\s)]*)?$/.test(v.replace(/-?var\(--s-\d+\)/g, "").replace(/env\([^)]*\)/g, "").replace(/calc|auto/g, "").replace(/\* -1/g, ""));
    const bad = decls.filter((d) => /^(padding|margin|gap|row-gap|column-gap)(-|$)/.test(d.prop) && !ok(d.value));
    expect(bad.map((d) => `${d.line}: ${d.prop}: ${d.value}`)).toEqual([]);
  });
  it("font sizes come from the --t-* scale, weights from --w-*", () => {
    const sizes = decls.filter((d) => d.prop === "font-size" && !/^var\(--t-[a-z0-9]+\)$/.test(d.value));
    expect(sizes.map((d) => `${d.line}: ${d.value}`)).toEqual([]);
    const weights = decls.filter((d) => d.prop === "font-weight" && !/^var\(--w-[a-z]+\)$/.test(d.value));
    expect(weights.map((d) => `${d.line}: ${d.value}`)).toEqual([]);
  });
  it("radii come from the radius tokens", () => {
    const bad = decls.filter((d) => d.prop === "border-radius" && !/^(var\(--radius-[a-z]+\)|0|50%)$/.test(d.value));
    expect(bad.map((d) => `${d.line}: ${d.value}`)).toEqual([]);
  });
  it("every token it references exists", () => {
    const used = new Set([...css.matchAll(/var\(--([a-z0-9-]+)/g)].map((m) => m[1]!));
    const local = new Set([...css.matchAll(/(?:^|[\s;{])--([a-z0-9-]+)\s*:/g)].map((m) => m[1]!));
    expect([...used].filter((u) => !defined.has(u) && !local.has(u))).toEqual([]);
  });
});

describe("macOS MoatUI uses the same tokens (Theme.swift: Space, TypeScale, Radius, BrandColor)", () => {
  const dir = resolve(__dirname, "../../macos/MoatKit/Sources/MoatUI");
  const files = readdirSync(dir).filter((f) => f.endsWith(".swift") && f !== "Theme.swift");
  const rules: [string, RegExp][] = [
    ["literal colour", /Color\(hex:|Color\.(white|black|red|blue|green|gray)\b/],
    ["literal stack spacing", /spacing: [1-9][0-9.]*\b/],
    ["literal padding", /\.padding\((\.[a-z]+, )?[0-9]/],
    ["literal corner radius", /cornerRadius: [0-9]/],
    ["literal font size", /\.system\(size: [0-9]/],
  ];
  for (const f of files)
    it(f, () => {
      const lines = readFileSync(resolve(dir, f), "utf8").split("\n");
      const bad = lines.flatMap((l, i) => rules.filter(([, re]) => re.test(l)).map(([what]) => `${f}:${i + 1} ${what}: ${l.trim()}`));
      expect(bad).toEqual([]);
    });
  it("the Swift scales match the design tokens", () => {
    const theme = readFileSync(resolve(dir, "Theme.swift"), "utf8");
    const json = JSON.parse(readFileSync(resolve(__dirname, "../../brand/design-tokens.json"), "utf8")) as { space: Record<string, number | string>; type: Record<string, number | string>; radius: Record<string, number> };
    for (const [k, v] of Object.entries(json.space)) if (k !== "note") expect(theme, `space ${k}`).toContain(`static let s${k}: CGFloat = ${v}`);
    for (const [k, v] of Object.entries(json.type)) if (k !== "note") expect(theme, `type ${k}`).toContain(`static let ${k === "2xl" ? "x2l" : k === "3xl" ? "x3l" : k}: CGFloat = ${v}`);
    for (const k of ["card", "inner", "control"]) expect(theme, `radius ${k}`).toContain(`static let ${k}: CGFloat = ${json.radius[k]}`);
  });
});
