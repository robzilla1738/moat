/**
 * Copy lint (docs/design.md, "Words"). Moat's own words in headings, labels, buttons, chips, banners and explanations
 * must be plain: the jargon list in brand/vocabulary.json may only appear under a Details disclosure, in a technical
 * page (data-tech), in monospace identifiers, or in data a device reported (rendered through Ident). The same status
 * vocabulary must be used on macOS: the Swift labels are checked against the same file.
 */
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import vocabulary from "../../brand/vocabulary.json";
import { App } from "./App";
import { demo } from "./data/demo";
import { StoreProvider } from "./data/store";
import type { Api } from "./data/api";
import { Activity, DecisionCard, IncidentDetail } from "./screens/Activity";
import { Overview } from "./screens/Overview";
import { AppDetail, AppsHome, Diagnostics, WhatChanged } from "./screens/Standalone";
import { DeviceDetail, Devices } from "./screens/Devices";
import { CoverageScreen } from "./screens/Coverage";
import { SessionDetail, Sessions } from "./screens/Sessions";
import { Rules } from "./screens/Rules";
import { BaselineView, CandidateReview, Learning, Packs } from "./screens/Learning";
import { SignIn } from "./screens/SignIn";

const JARGON = new RegExp(`\\b(${vocabulary.jargon.terms.join("|")})\\b`, "i");
const go = () => {};
const noApi: Api = { get: async () => Promise.reject(new Error("offline")), post: async () => Promise.reject(new Error("offline")) };

const SKIP_CLASS = /\b(ident|mono|code|details-body|chain-exe)\b/;
const VOID = new Set(["input", "br", "img", "hr", "meta", "link", "source", "wbr"]);
const decode = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&");

/** The text a person reads first: everything except disclosures' bodies, technical regions and untrusted data. */
export function primaryText(html: string): string[] {
  const out: string[] = [];
  const stack: boolean[] = [];
  for (const m of html.matchAll(/<(\/?)([a-zA-Z0-9]+)([^>]*?)(\/?)>|([^<]+)/g)) {
    const [, close, tag, attrs, selfClose, text] = m;
    if (text !== undefined) {
      if (!stack.some(Boolean)) {
        const t = decode(text).trim();
        if (t) out.push(t);
      }
      continue;
    }
    const name = tag!.toLowerCase();
    if (close) {
      stack.pop();
      continue;
    }
    if (VOID.has(name) || selfClose) continue;
    const cls = /class="([^"]*)"/.exec(attrs ?? "")?.[1] ?? "";
    const skip = (SKIP_CLASS.test(cls) && !/\bdetails-plain\b/.test(cls)) || /\bdata-tech=/.test(attrs ?? "") || ["pre", "code", "svg", "option", "title", "textarea"].includes(name);
    stack.push(skip);
  }
  return out;
}

function demoHtml(el: ReactElement) {
  return renderToStaticMarkup(<StoreProvider options={{ initial: { mode: "demo", data: demo, status: "ready" } }}>{el}</StoreProvider>);
}
function liveHtml(el: ReactElement, status: "ready" | "unreachable" | "signed_out" = "ready", role: "owner" | "viewer" = "owner") {
  return renderToStaticMarkup(
    <StoreProvider options={{ initial: { mode: "live", data: status === "signed_out" ? undefined : { ...demo, demo: false, viewer: { name: "robert", role } }, status }, api: noApi }}>{el}</StoreProvider>,
  );
}

const views: [string, string][] = [
  ["shell + Apps", demoHtml(<App />)],
  ["Apps", demoHtml(<AppsHome go={go} />)],
  ["Overview", demoHtml(<Overview go={go} />)],
  ["Activity", demoHtml(<Activity go={go} />)],
  ...demo.incidents.map((i) => [`Alert ${i.id}`, demoHtml(<IncidentDetail id={i.id} go={go} />)] as [string, string]),
  ["Devices", demoHtml(<Devices go={go} />)],
  ...demo.devices.map((d) => [`Device ${d.id}`, demoHtml(<DeviceDetail id={d.id} go={go} />)] as [string, string]),
  ["Coverage & recovery", demoHtml(<CoverageScreen go={go} />)],
  ["What changed?", demoHtml(<WhatChanged go={go} />)],
  ["Diagnostics (sample)", demoHtml(<Diagnostics />)],
  ["Tasks", demoHtml(<Sessions go={go} />)],
  ...demo.sessions.map((s) => [`Task ${s.id}`, demoHtml(<SessionDetail id={s.id} go={go} />)] as [string, string]),
  ["Rules", demoHtml(<Rules go={go} />)],
  ["Learn", demoHtml(<Learning go={go} />)],
  ["Review 1", demoHtml(<CandidateReview id="cand-demo-1" go={go} />)],
  ["Review 2", demoHtml(<CandidateReview id="cand-demo-2" go={go} />)],
  ["Approved list", demoHtml(<BaselineView id="base-demo-1" go={go} />)],
  ["Rule packs", demoHtml(<Packs />)],
  ["App (sample)", demoHtml(<AppDetail id="claude" go={go} />)],
  ["Sign in", liveHtml(<SignIn />, "signed_out")],
  ["Controller unreachable", liveHtml(<App />, "unreachable")],
  ["Viewer decision", liveHtml(<DecisionCard incident={demo.incidents[0]!} go={go} />, "ready", "viewer")],
];

describe("plain-language copy", () => {
  it("the parser keeps primary text and drops disclosures, identifiers and technical regions", () => {
    const t = primaryText('<h1>Rules</h1><details class="details"><summary>Technical details</summary><div class="details-body">policy revision 4</div></details><span class="ident">endpoint.example</span><div data-tech=""><p>evidence age</p></div><p>Allowed &amp; checked</p>');
    expect(t).toEqual(["Rules", "Technical details", "Allowed & checked"]);
  });
  for (const [name, html] of views)
    it(`${name}: no jargon outside Details`, () => {
      const hits = primaryText(html).filter((t) => JARGON.test(t));
      expect(hits).toEqual([]);
    });
});

// ------------------------------------------------------------------------------------------------------------ macOS
const ui = resolve(__dirname, "../../macos/MoatKit/Sources/MoatUI");
const kit = resolve(__dirname, "../../macos/MoatKit/Sources/MoatKit");
const swift = Object.fromEntries(readdirSync(ui).filter((f) => f.endsWith(".swift")).map((f) => [f, readFileSync(resolve(ui, f), "utf8")]));
const models = readFileSync(resolve(kit, "Models.swift"), "utf8");

/** String literals in the primary positions of MoatUI: headers, section titles, buttons, chips, empty states and Text("…"). Text(verbatim:) is for data and technical detail. */
function swiftPrimary(src: string): string[] {
  const out: string[] = [];
  const lit = String.raw`"((?:[^"\\]|\\.)*)"`;
  const patterns = [
    new RegExp(String.raw`ScreenHeader\([^)]*?(?:eyebrow|title|dim): ${lit}`, "g"),
    new RegExp(String.raw`SectionTitle\(text: ${lit}`, "g"),
    new RegExp(String.raw`MoatButton\(title: ${lit}`, "g"),
    new RegExp(String.raw`Pill\(text: ${lit}`, "g"),
    new RegExp(String.raw`EmptyStateView\([^)]*?(?:title|text): ${lit}`, "g"),
    new RegExp(String.raw`(?<![A-Za-z])Text\(${lit}`, "g"),
    new RegExp(String.raw`Label\(${lit}`, "g"),
    new RegExp(String.raw`Toggle\(${lit}`, "g"),
    new RegExp(String.raw`Button\(${lit}`, "g"),
  ];
  for (const re of patterns) for (const m of src.matchAll(re)) out.push(m[1]!.replace(/\\\((?:[^()]|\([^()]*\))*\)/g, "…"));
  return out;
}

describe("macOS uses the same words", () => {
  const v = vocabulary as unknown as { coverage: Record<string, { label: string }>; macCoverage: Record<string, string>; support: Record<string, { label: string }>; verdict: Record<string, { label: string }> };
  it("coverage labels match the shared vocabulary", () => {
    const body = models.slice(models.indexOf("public enum CoverageLevel"), models.indexOf("public var claim"));
    const cases: Record<string, string> = { observed: "observed", enforced: "enforced", degraded: "degraded", isolated: "isolated", recoveryRequired: "recovery-required", rollbackPending: "rollback-pending", unknown: "unknown" };
    for (const [swiftCase, raw] of Object.entries(cases)) {
      const m = new RegExp(`case \\.${swiftCase}: return "([^"]+)"`).exec(body);
      expect(m?.[1], swiftCase).toBe(v.coverage[v.macCoverage[raw]!]!.label);
    }
  });
  it("support and verdict labels match", () => {
    const comp = swift["Components.swift"]!;
    for (const [k, e] of Object.entries(v.support)) expect(comp, k).toContain(`case .${k}: return "${e.label}"`);
    for (const k of ["blocked", "allowed", "observed", "isolated"]) expect(comp, k).toContain(`"${v.verdict[k]!.label}"`);
  });
  for (const [file, src] of Object.entries(swift))
    it(`${file}: no jargon in primary strings`, () => {
      expect(swiftPrimary(src).filter((t) => JARGON.test(t))).toEqual([]);
    });
});
