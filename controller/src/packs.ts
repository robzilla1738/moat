/**
 * W14 maintained workflow packs (packs/workflows/*.json, schema moat.workflow_pack.v1). A pack is signed-or-not data;
 * it never creates owner authorization. Applying modules produces a normal policy proposal whose broadening needs the
 * owner key, exactly like any other change. Each module carries rule material, rationale, required capabilities,
 * compatible versions, expected breakage if omitted, provenance and a test recipe.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { HttpError } from "./db.ts";
import type { Controller, Principal } from "./controller.ts";

export interface PackModule { id: string; name: string; optional: boolean; rationale: string; required_capabilities: string[]; compatible_versions: Record<string, string>; expected_breakage_if_omitted: string; provenance: string; rules: string; test_recipe: string[] }
export interface WorkflowPack { schema: "moat.workflow_pack.v1"; id: string; version: string; name: string; description: string; profile: string; modules: PackModule[] }

const REQUIRED: (keyof PackModule)[] = ["id", "name", "rationale", "required_capabilities", "compatible_versions", "expected_breakage_if_omitted", "provenance", "rules", "test_recipe"];

export function packProblems(p: WorkflowPack): string[] {
  const out: string[] = [];
  if (p.schema !== "moat.workflow_pack.v1") out.push(`${p.id}: unknown schema ${p.schema}`);
  if (!/^\d{4}\.\d{1,2}\.\d+$/.test(p.version ?? "")) out.push(`${p.id}: version must be YYYY.M.N`);
  if (!p.modules?.length) out.push(`${p.id}: no modules`);
  for (const m of p.modules ?? []) {
    for (const k of REQUIRED) {
      const v = m[k];
      if (v === undefined || v === null || (typeof v === "string" && !v.trim()) || (Array.isArray(v) && !v.length)) out.push(`${p.id}/${m.id ?? "?"}: missing ${k}`);
    }
    if (/\bhosts\s*=\s*\[[^\]]*\*/.test(m.rules ?? "")) out.push(`${p.id}/${m.id}: wildcard hosts are not allowed in maintained packs`);
    if (/^\s*id\s*=/m.test(m.rules ?? "")) out.push(`${p.id}/${m.id}: rule ids are assigned by Moat (pack/module/version)`);
  }
  return out;
}

export function loadPacks(dir: string): WorkflowPack[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as WorkflowPack);
}

/** The TOML a set of modules adds, with stable ids and provenance naming pack, module and version. */
export function packRules(p: WorkflowPack, moduleIds: string[]): string {
  const mods = moduleIds.map((m) => p.modules.find((x) => x.id === m) ?? (() => { throw new HttpError(400, `pack ${p.id} has no module ${m}`); })());
  return mods.map((m) => `\n[[rules]]\nid = "pack-${p.id}-${m.id}"\ndescription = ${JSON.stringify(`${p.name} / ${m.name} (${p.id}@${p.version}): ${m.rationale}`)}\n${m.rules}\nprovenance = { kind = "service_pack", reference = "${p.id}/${m.id}@${p.version}" }\n`).join("");
}

/** Propose enabling modules. The proposal is reviewed and approved like any other; pack authenticity is not consent. */
export async function proposePack(c: Controller, actor: Principal, packs: WorkflowPack[], b: { pack?: unknown; modules?: unknown }) {
  c.require(actor, "owner");
  const p = packs.find((x) => x.id === b.pack);
  if (!p) throw new HttpError(404, "no such pack");
  const problems = packProblems(p);
  if (problems.length) throw new HttpError(422, problems.join("; "));
  const ids = Array.isArray(b.modules) ? (b.modules as string[]) : [];
  if (!ids.length) throw new HttpError(400, "choose the modules to enable; nothing is enabled by default");
  const cur = c.currentRevision();
  if (!cur) throw new HttpError(409, "no policy to extend yet");
  const omitted = p.modules.filter((m) => !ids.includes(m.id)).map((m) => ({ module: m.id, expected_breakage: m.expected_breakage_if_omitted }));
  const prop = await c.propose(actor, cur.source + packRules(p, ids), `Enable ${p.id}@${p.version}: ${ids.join(", ")}`);
  return { proposal: prop, omitted_modules: omitted, test_recipes: p.modules.filter((m) => ids.includes(m.id)).map((m) => ({ module: m.id, steps: m.test_recipe })), note: "Replay of recorded traffic is an estimate; canary on one device and run each module's test recipe before relying on it." };
}
