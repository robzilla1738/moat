/**
 * The controller never re-implements policy semantics: validation, compilation, diff and simulation come from the
 * Rust core through `moatctl` (argv only, never a shell). Policy text goes through a temp file.
 */
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface MoatctlResult { code: number; stdout: string; stderr: string }

export class Moatctl {
  bin: string;
  constructor(bin = process.env.MOATCTL ?? "moatctl") {
    this.bin = bin;
  }

  run(args: string[], files: Record<string, string> = {}): Promise<MoatctlResult> {
    const dir = mkdtempSync(join(tmpdir(), "moatctl-"));
    const resolved = args.map((a) => (a.startsWith("@") && a.slice(1) in files ? join(dir, a.slice(1)) : a));
    for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
    return new Promise((resolve) => {
      execFile(this.bin, resolved, { maxBuffer: 32 * 1024 * 1024, timeout: 30_000 }, (err, stdout, stderr) => {
        rmSync(dir, { recursive: true, force: true });
        const code = err ? (typeof (err as NodeJS.ErrnoException & { code?: unknown }).code === "number" ? ((err as unknown as { code: number }).code) : 1) : 0;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      });
    });
  }

  /**
   * `ok`: valid and compiles fleet-wide for every adapter. `schemaOk`: the policy itself is valid (it parsed and only
   * fleet-wide adapter compilation failed), which a device-targeted compile may still satisfy (issue #26).
   */
  async validate(policy: string): Promise<{ ok: boolean; schemaOk: boolean; errors: string[]; adapters: unknown[] }> {
    const r = await this.run(["--json", "validate", "@p.toml"], { "p.toml": policy });
    const j = parse(r);
    const adapters = (j.adapters as { adapter?: string; compiles?: boolean; errors?: string[] }[] | undefined) ?? [];
    const adapterErrors = adapters.filter((a) => a.compiles === false).flatMap((a) => (a.errors ?? ["does not compile"]).map((e) => `${a.adapter}: ${e}`));
    const schemaErrors = (j.errors as string[] | undefined) ?? (j.error ? [String(j.error)] : null);
    return { ok: r.code === 0 && j.ok !== false, schemaOk: !schemaErrors && adapters.length > 0, errors: schemaErrors ?? adapterErrors, adapters };
  }

  async diff(oldPolicy: string, newPolicy: string): Promise<{ broadening: boolean; diff: Record<string, unknown> }> {
    const r = await this.run(["--json", "diff", "@old.toml", "@new.toml"], { "old.toml": oldPolicy, "new.toml": newPolicy });
    if (r.code !== 0 && r.code !== 3) throw new Error(`moatctl diff failed: ${r.stderr || r.stdout}`);
    const j = parse(r);
    return { broadening: j.broadening === true, diff: (j.diff as Record<string, unknown>) ?? {} };
  }

  /**
   * Compile base + `moat.grant.v1` overlays (`--grants`, W03): the core renders each grant's exact rule.
   * `devices` (issue #26): compile for these devices only (`--device`, repeatable). Rules scoped to other devices are
   * left out with a report and the signed snapshot installs only on a listed device. Empty: fleet-wide compile, which
   * refuses a rule this adapter cannot enforce even when it is scoped to another platform's device.
   */
  async compile(policy: string, adapter: "linux" | "macos" | "dns", revision: number, issuedAt: Date, rollbackOf?: number | null, grants: unknown[] = [], devices: string[] = []): Promise<{ ok: true; snapshot: string } | { ok: false; error: string }> {
    const args = ["compile", "@p.toml", "--adapter", adapter, "--revision", String(revision), "--issued-at", issuedAt.toISOString()];
    if (rollbackOf) args.push("--rollback-of", String(rollbackOf));
    for (const d of devices) args.push("--device", d);
    const files: Record<string, string> = { "p.toml": policy };
    if (grants.length) {
      args.push("--grants", "@grants.json");
      files["grants.json"] = JSON.stringify(grants);
    }
    const r = await this.run(args, files);
    if (r.code !== 0) return { ok: false, error: (r.stderr || r.stdout).trim() };
    return { ok: true, snapshot: r.stdout.trim() };
  }

  /** Canonical normalized policy JSON (the core's view: sets resolved, defaults filled). */
  async normalize(policy: string): Promise<Record<string, unknown>> {
    const r = await this.run(["--json", "normalize", "@p.toml"], { "p.toml": policy });
    if (r.code !== 0) throw new Error(`moatctl normalize failed: ${r.stderr || r.stdout}`);
    return parse(r);
  }

  /** Deterministic explanation of one flow attempt against a policy (winning rule, overridden rules, notes). */
  async explain(policy: string, attempt: unknown): Promise<Record<string, unknown>> {
    const r = await this.run(["--json", "explain", "--flow", "@f.json", "@p.toml"], { "p.toml": policy, "f.json": JSON.stringify(attempt) });
    if (r.code !== 0) throw new Error(`moatctl explain failed: ${r.stderr || r.stdout}`);
    return parse(r);
  }

  async simulate(current: string, proposed: string, observationsJsonl: string, unacknowledged: string[]): Promise<Record<string, unknown>> {
    const args = ["--json", "simulate", "@cur.toml", "@new.toml", "--observations", "@obs.jsonl", ...unacknowledged.flatMap((d) => ["--unacknowledged", d])];
    const r = await this.run(args, { "cur.toml": current, "new.toml": proposed, "obs.jsonl": observationsJsonl });
    if (r.code !== 0) throw new Error(`moatctl simulate failed: ${r.stderr || r.stdout}`);
    return parse(r);
  }
}

function parse(r: MoatctlResult): Record<string, unknown> {
  try {
    return JSON.parse(r.stdout) as Record<string, unknown>;
  } catch {
    return { ok: false, error: (r.stderr || r.stdout).trim() };
  }
}
