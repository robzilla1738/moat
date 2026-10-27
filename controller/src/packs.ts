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

export type CellSupport = "supported" | "untested" | "unsupported" | "unknown";

/** Hosts, CIDRs and ports a module's rule material names (for the delta view; the compiler stays authoritative). */
export function moduleDestinations(m: PackModule) {
  const list = (k: string) => [...(m.rules.match(new RegExp(`\\b${k}\\s*=\\s*\\[([^\\]]*)\\]`))?.[1]?.matchAll(/"([^"]+)"/g) ?? [])].map((x) => x[1]!);
  const ports = (m.rules.match(/\bports\s*=\s*\[([^\]]*)\]/)?.[1] ?? "").split(",").map((s) => Number(s.trim())).filter((n) => Number.isInteger(n) && n > 0);
  const transport = m.rules.match(/\btransport\s*=\s*"([^"]+)"/)?.[1] ?? null;
  return { hosts: list("hosts"), cidrs: list("cidrs"), ports, transport };
}

/**
 * A pack's effective delta against the current policy and the enrolled devices: per module, whether it is already
 * enabled, which destinations it would newly allow, and per device whether its required capabilities are supported
 * there. A cell that is not `supported` is skipped on that device with a report (`on_unsupported = skip_with_report`),
 * so the module would not take effect there.
 */
export function packDelta(c: Controller, p: WorkflowPack) {
  const cur = c.currentRevision();
  const source = cur?.source ?? "";
  const devices = (c.db.prepare("SELECT id, name, platform, capabilities FROM devices WHERE revoked_at IS NULL ORDER BY id").all() as { id: string; name: string; platform: string; capabilities: string | null }[]).filter((d) => d.platform !== "dns");
  const modules = p.modules.map((m) => {
    const enabled = source.includes(`id = "pack-${p.id}-${m.id}"`);
    const dest = moduleDestinations(m);
    const named = [...dest.hosts, ...dest.cidrs];
    const newly = enabled ? [] : named.filter((h) => !source.includes(`"${h}"`));
    const cells = devices.map((d) => {
      const caps = d.capabilities ? ((JSON.parse(d.capabilities) as { capabilities?: Record<string, { support?: string }> }).capabilities ?? {}) : {};
      const per = m.required_capabilities.map((k) => ({ capability: k, support: (["supported", "untested", "unsupported"].includes(caps[k]?.support ?? "") ? caps[k]!.support : "unknown") as CellSupport }));
      const support: CellSupport = per.every((x) => x.support === "supported") ? "supported" : per.some((x) => x.support === "unsupported") ? "unsupported" : per.some((x) => x.support === "unknown") ? "unknown" : "untested";
      return { device_id: d.id, device: d.name, platform: d.platform, support, missing: per.filter((x) => x.support !== "supported"), takes_effect: support === "supported" };
    });
    return { id: m.id, name: m.name, optional: m.optional, rationale: m.rationale, required_capabilities: m.required_capabilities, enabled, destinations: dest, newly_allowed: newly, expected_breakage_if_omitted: m.expected_breakage_if_omitted, provenance: m.provenance, compatible_versions: m.compatible_versions, test_recipe: m.test_recipe, cells, unsupported_cells: cells.filter((x) => !x.takes_effect).length };
  });
  return {
    pack: { id: p.id, version: p.version, name: p.name, description: p.description, profile: p.profile },
    revision: cur?.revision ?? null,
    problems: packProblems(p),
    devices: devices.map((d) => ({ id: d.id, name: d.name, platform: d.platform })),
    modules,
    effective: { modules_to_enable: modules.filter((m) => !m.enabled).length, newly_allowed: [...new Set(modules.flatMap((m) => m.newly_allowed))], unsupported_cells: modules.reduce((n, m) => n + m.unsupported_cells, 0) },
    note: "The delta is computed from the pack's rule material and the devices' advertised capabilities. Enabling modules is an owner-authorized broadening proposal; replay of recorded traffic is an estimate.",
  };
}
