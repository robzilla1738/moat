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

  async validate(policy: string): Promise<{ ok: boolean; errors: string[]; adapters: unknown[] }> {
    const r = await this.run(["--json", "validate", "@p.toml"], { "p.toml": policy });
    const j = parse(r);
    return { ok: r.code === 0 && j.ok !== false, errors: (j.errors as string[] | undefined) ?? (j.error ? [String(j.error)] : []), adapters: (j.adapters as unknown[] | undefined) ?? [] };
  }

  async diff(oldPolicy: string, newPolicy: string): Promise<{ broadening: boolean; diff: Record<string, unknown> }> {
    const r = await this.run(["--json", "diff", "@old.toml", "@new.toml"], { "old.toml": oldPolicy, "new.toml": newPolicy });
    if (r.code !== 0 && r.code !== 3) throw new Error(`moatctl diff failed: ${r.stderr || r.stdout}`);
    const j = parse(r);
    return { broadening: j.broadening === true, diff: (j.diff as Record<string, unknown>) ?? {} };
  }

  async compile(policy: string, adapter: "linux" | "macos" | "dns", revision: number, issuedAt: Date, rollbackOf?: number | null): Promise<{ ok: true; snapshot: string } | { ok: false; error: string }> {
    const args = ["compile", "@p.toml", "--adapter", adapter, "--revision", String(revision), "--issued-at", issuedAt.toISOString()];
    if (rollbackOf) args.push("--rollback-of", String(rollbackOf));
    const r = await this.run(args, { "p.toml": policy });
    if (r.code !== 0) return { ok: false, error: (r.stderr || r.stdout).trim() };
    return { ok: true, snapshot: r.stdout.trim() };
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
