/**
 * Mock AdGuard Home (v0.107 API) and Pi-hole (FTL v6 API) servers for the W16 adapter tests. Real HTTP on loopback,
 * shaped after the documented APIs (see fixtures/). They are not a live resolver: the live check is on the
 * device-proof list in docs/integrations.md.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const FIXTURES = join(import.meta.dirname, "fixtures");
export const fixtureJson = (name: string) => JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as Record<string, unknown>;

export interface MockBase { url: string; close(): Promise<void>; requests: string[] }

async function listen(srv: Server): Promise<string> {
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}
const close = (srv: Server) => () => new Promise<void>((r) => { srv.closeAllConnections(); srv.close(() => r()); });

/** AdGuard Home: basic auth, `/control/status`, `/control/querylog?limit&older_than` newest first with `oldest`. */
export async function mockAdguard(o: { user?: string; pass?: string; version?: string; entries?: Record<string, unknown>[] } = {}) {
  const state = { version: o.version ?? "v0.107.52", entries: [...(o.entries ?? ((fixtureJson("adguard-querylog.json").data as Record<string, unknown>[])))], down: false };
  const requests: string[] = [];
  const auth = `Basic ${Buffer.from(`${o.user ?? "moat"}:${o.pass ?? "s3cret"}`).toString("base64")}`;
  const srv = createServer((req, res) => {
    requests.push(req.url ?? "");
    const send = (code: number, body: unknown) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== auth) return send(401, { message: "unauthorized" });
    const u = new URL(req.url ?? "/", "http://x");
    if (u.pathname === "/control/status") return send(200, { version: state.version, running: true, protection_enabled: true });
    if (u.pathname === "/control/querylog") {
      const limit = Number(u.searchParams.get("limit") ?? 500);
      const older = u.searchParams.get("older_than");
      let start = 0;
      if (older) {
        const i = state.entries.map((e) => e.time).lastIndexOf(older);
        start = i < 0 ? state.entries.findIndex((e) => Date.parse(String(e.time)) < Date.parse(older)) : i + 1;
        if (start < 0) start = state.entries.length;
      }
      const data = state.entries.slice(start, start + limit);
      return send(200, { data, oldest: data.length ? data[data.length - 1]!.time : "" });
    }
    send(404, { message: "not found" });
  });
  const url = await listen(srv);
  return { url, close: close(srv), requests, state };
}

/** Pi-hole v6: `POST /api/auth` session, `sid` header, `/api/info/version`, `/api/queries?length&start&cursor`. */
export async function mockPihole(o: { password?: string; version?: string; queries?: Record<string, unknown>[]; v5?: boolean } = {}) {
  const state = { version: o.version ?? "v6.1", queries: [...(o.queries ?? ((fixtureJson("pihole-queries.json").queries as Record<string, unknown>[])))], sids: new Set<string>(), logins: 0, v5: o.v5 ?? false };
  const requests: string[] = [];
  const srv = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    const send = (code: number, body: unknown) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    const u = new URL(req.url ?? "/", "http://x");
    if (state.v5) return send(404, { error: "not found" }); // Pi-hole v5 has no /api
    if (u.pathname === "/api/auth" && req.method === "POST") {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        const ok = (JSON.parse(b || "{}") as { password?: string }).password === (o.password ?? "pw");
        if (!ok) return send(401, { session: { valid: false, totp: false, sid: null, validity: -1, message: "password incorrect" } });
        state.logins++;
        const sid = `sid${state.logins}`;
        state.sids.add(sid);
        send(200, { session: { valid: true, totp: false, sid, csrf: "x", validity: 1800, message: "app-password correct" } });
      });
      return;
    }
    if (!state.sids.has(String(req.headers.sid ?? ""))) return send(401, { error: { key: "unauthorized", message: "Unauthorized" } });
    if (u.pathname === "/api/info/version") return send(200, { version: { core: { local: { version: "v6.0" } }, web: { local: { version: "v6.0" } }, ftl: { local: { version: state.version } } } });
    if (u.pathname === "/api/queries") {
      const length = Number(u.searchParams.get("length") ?? 100);
      const start = Number(u.searchParams.get("start") ?? 0);
      const cursor = u.searchParams.get("cursor");
      const pool = cursor ? state.queries.filter((q) => Number(q.id) <= Number(cursor)) : state.queries;
      const rows = pool.slice(start, start + length);
      return send(200, { queries: rows, cursor: state.queries.length ? Number(state.queries[0]!.id) : null, recordsTotal: state.queries.length, recordsFiltered: pool.length, draw: 0, took: 0.001 });
    }
    send(404, { error: { key: "not_found" } });
  });
  const url = await listen(srv);
  return { url, close: close(srv), requests, state };
}

/** AdGuard entry for a given client/name at an ISO time. */
export const ag = (time: string, client: string, name: string, reason = "NotFilteredNotFound", type = "A") => ({ client, question: { class: "IN", name, type }, reason, status: "NOERROR", time });
/** Pi-hole query row. */
export const ph = (id: number, epoch: number, client: string, domain: string, status = "FORWARDED") => ({ id, time: epoch, type: "A", status, domain, client: { ip: client, name: null }, reply: { type: "IP", time: 1 } });
