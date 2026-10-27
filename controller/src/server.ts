/**
 * HTTP API (node:http, no framework). Owner/viewer/launcher/agent principals use bearer tokens; endpoints use
 * device-signed requests and receive controller-signed responses. Listen on the tailnet or LAN interface only;
 * localhost is not treated as trusted — every route authenticates.
 */
import { apps, appDetail, diagnostics, whatChanged } from "./standalone.ts";
import { approveCandidate, baseline, candidate, closeCapture, driftReview, importCandidate, muteIncident, proposeBaseline, retireBaseline, startCapture } from "./learning.ts";
import { loadPacks, packProblems, proposePack, type WorkflowPack } from "./packs.ts";
import { fileURLToPath } from "node:url";
let packCache: WorkflowPack[] | null = null;
const workflowPacks = () => (packCache ??= loadPacks(join(fileURLToPath(new URL("../../packs/workflows", import.meta.url)))));
import { advanceRollout, createRollout, reconciliation, resolveLocalChange, rolloutStatus } from "./fleet.ts";
export const CONTROLLER_VERSION = "0.1.0";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { HttpError } from "./db.ts";
import type { Controller, Principal } from "./controller.ts";
import { dnsClients } from "./dns.ts";

const MAX_BODY = 4 * 1024 * 1024;

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > MAX_BODY) throw new HttpError(413, "body too large");
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

type Handler = (ctx: { c: Controller; p: Principal | null; body: string; json: Record<string, unknown>; params: string[]; query: URLSearchParams; req: IncomingMessage }) => unknown | Promise<unknown>;
interface Route { method: string; re: RegExp; h: Handler; device?: boolean }

const routes: Route[] = [];
const r = (method: string, path: string, h: Handler, device = false) => routes.push({ method, re: new RegExp(`^${path.replace(/:[a-z_]+/g, "([^/]+)")}$`), h, device });

// --- owner / viewer
r("GET", "/v1/me", ({ c, p }) => {
  const me = c.require(p, "owner", "viewer", "launcher", "agent");
  return { id: me.id, name: me.name, role: me.role };
});
r("GET", "/v1/overview", ({ c, p }) => (c.require(p, "owner", "viewer"), c.overview()));
r("GET", "/v1/devices", ({ c, p }) => (c.require(p, "owner", "viewer"), c.devices()));
r("POST", "/v1/devices/:id/revoke", ({ c, p, params }) => c.revokeDevice(c.require(p, "owner"), params[0]!));
r("POST", "/v1/enrollment-codes", ({ c, p, json }) => c.createEnrollmentCode(c.require(p, "owner"), Array.isArray(json.device_groups) ? (json.device_groups as string[]) : []));
r("GET", "/v1/incidents", ({ c, p, query }) => (c.require(p, "owner", "viewer"), c.incidents(query.get("state") ?? undefined)));
r("GET", "/v1/incidents/:id", ({ c, p, params }) => (c.require(p, "owner", "viewer"), c.incident(params[0]!)));
r("POST", "/v1/incidents/:id/acknowledge", ({ c, p, params, json }) => c.acknowledge(c.require(p, "owner"), params[0]!, json.expected_revision));
r("POST", "/v1/incidents/:id/resolve", ({ c, p, params, json }) => c.resolve(c.require(p, "owner"), params[0]!, json.expected_revision));
r("GET", "/v1/r/:ref", ({ c, p, params }) => {
  c.require(p, "owner", "viewer");
  const iid = c.notifier.resolveRef(params[0]!);
  if (!iid) throw new HttpError(404, "unknown reference");
  return c.incident(iid);
});
r("POST", "/v1/actions/allow-once/plan", ({ c, p, json }) => c.planAllowOnce(c.require(p, "owner"), json));
r("POST", "/v1/actions/allow-once", ({ c, p, json }) => c.allowOnce(c.require(p, "owner"), json));
r("POST", "/v1/grants/plan", ({ c, p, json }) => c.planGrant(c.require(p, "owner"), json));
r("POST", "/v1/grants/commit", ({ c, p, json }) => c.commitGrant(c.require(p, "owner"), json));
r("GET", "/v1/issuers", ({ c, p }) => (c.require(p, "owner", "viewer"), c.issuers()));
r("POST", "/v1/issuers", ({ c, p, json }) => c.registerIssuer(c.require(p, "owner"), json));
r("POST", "/v1/issuers/:id/revoke", ({ c, p, params }) => c.revokeIssuer(c.require(p, "owner"), params[0]!));
r("GET", "/v1/publications", ({ c, p }) => (c.require(p, "owner", "viewer"), c.publications()));
r("GET", "/v1/flows", ({ c, p, query }) => (c.require(p, "owner", "viewer"), c.flows.recent({ deviceId: query.get("device") ?? undefined, verdict: query.get("verdict") ?? undefined, limit: Number(query.get("limit") ?? 100) })));
r("GET", "/v1/rollups", ({ c, p, query }) => (c.require(p, "owner", "viewer"), c.flows.rollups({ sinceHour: query.get("since") ?? new Date(Date.now() - 86400_000).toISOString(), deviceId: query.get("device") ?? undefined })));
r("GET", "/v1/policy/revisions", ({ c, p }) => (c.require(p, "owner", "viewer"), c.revisions()));
r("POST", "/v1/policy/proposals", ({ c, p, json }) => c.propose(c.require(p, "owner", "agent"), String(json.source ?? ""), String(json.message ?? "")));
r("GET", "/v1/policy/proposals/:id", ({ c, p, params }) => (c.require(p, "owner", "viewer", "agent"), c.proposal(params[0]!)));
r("POST", "/v1/policy/proposals/:id/approve", ({ c, p, params, json }) => c.approve(c.require(p, "owner"), params[0]!, (json.owner_authorization as never) ?? null));
r("GET", "/v1/policy/untargeted", ({ c, p }) => (c.require(p, "owner", "viewer"), { devices: c.untargetedDevices() }));
r("POST", "/v1/policy/retarget", ({ c, p }) => c.retarget(c.require(p, "owner")));
r("POST", "/v1/policy/rollback", ({ c, p, json }) => c.rollback(c.require(p, "owner"), Number(json.to_revision), String(json.message ?? "")));
r("GET", "/v1/grants", ({ c, p }) => (c.require(p, "owner", "viewer"), c.grants()));
r("POST", "/v1/grants", ({ c, p, json }) => c.createGrant(c.require(p, "owner"), json as never));
r("GET", "/v1/grants/:id", ({ c, p, params }) => (c.require(p, "owner", "viewer"), c.grantStatus(params[0]!)));
r("POST", "/v1/grants/:id/revoke", ({ c, p, params }) => c.revokeGrant(c.require(p, "owner"), params[0]!));
r("GET", "/v1/sessions", ({ c, p, query }) => (c.require(p, "owner", "viewer", "launcher"), c.sessions(query.get("device") ?? undefined)));
// W12 standalone read models: Apps-first UI, app detail, "What changed?", local diagnostics.
r("GET", "/v1/apps", ({ c, p, query }) => (c.require(p, "owner", "viewer"), apps(c, { deviceId: query.get("device") ?? undefined })));
r("GET", "/v1/apps/:id", async ({ c, p, params }) => {
  c.require(p, "owner", "viewer");
  const d = await appDetail(c, params[0]!);
  if (!d) throw new HttpError(404, "no app with that identity was seen in the last 7 days");
  return d;
});
r("GET", "/v1/what-changed", ({ c, p, query }) => (c.require(p, "owner", "viewer"), whatChanged(c, { device: query.get("device"), app: query.get("app"), working: query.get("working"), failing: query.get("failing") })));
r("GET", "/v1/diagnostics", ({ c, p }) => (c.require(p, "owner", "viewer"), diagnostics(c, CONTROLLER_VERSION)));
// W13 fleet: desired/current reconciliation, staged rollouts, owner resolution of offline local changes.
r("GET", "/v1/reconciliation", ({ c, p }) => (c.require(p, "owner", "viewer"), reconciliation(c)));
r("POST", "/v1/rollouts", ({ c, p, json }) => createRollout(c, c.require(p, "owner"), json));
r("GET", "/v1/rollouts/:rev", ({ c, p, params }) => (c.require(p, "owner", "viewer"), rolloutStatus(c, Number(params[0]))));
r("POST", "/v1/rollouts/:rev/advance", ({ c, p, params }) => advanceRollout(c, c.require(p, "owner"), Number(params[0])));
r("POST", "/v1/devices/:id/local-change/resolve", ({ c, p, params, json }) => resolveLocalChange(c, c.require(p, "owner"), params[0]!, json.resolution));
// W14 learning: bounded capture → candidate → owner review → immutable baseline → drift (a new candidate) → proposal.
r("POST", "/v1/learning/captures", ({ c, p, json }) => startCapture(c, c.require(p, "owner"), json));
r("POST", "/v1/learning/captures/:id/close", ({ c, p, params }) => closeCapture(c, c.require(p, "owner"), params[0]!));
r("GET", "/v1/learning/candidates/:id", ({ c, p, params }) => (c.require(p, "owner", "viewer"), candidate(c, params[0]!)));
r("POST", "/v1/learning/candidates/:id/approve", ({ c, p, params, json }) => approveCandidate(c, c.require(p, "owner"), params[0]!, json));
r("POST", "/v1/learning/import", ({ c, p, json }) => importCandidate(c, c.require(p, "owner"), json));
r("GET", "/v1/learning/baselines/:id", ({ c, p, params }) => (c.require(p, "owner", "viewer"), baseline(c, params[0]!)));
r("POST", "/v1/learning/baselines/:id/drift", ({ c, p, params }) => driftReview(c, c.require(p, "owner"), params[0]!));
r("POST", "/v1/learning/baselines/:id/propose", ({ c, p, params }) => proposeBaseline(c, c.require(p, "owner"), params[0]!));
r("POST", "/v1/learning/baselines/:id/retire", ({ c, p, params, json }) => retireBaseline(c, c.require(p, "owner"), params[0]!, json.reason));
r("GET", "/v1/packs", ({ c, p }) => (c.require(p, "owner", "viewer"), workflowPacks().map((x) => ({ ...x, problems: packProblems(x) }))));
r("POST", "/v1/packs/propose", ({ c, p, json }) => proposePack(c, c.require(p, "owner"), workflowPacks(), json));
r("POST", "/v1/incidents/:id/mute", ({ c, p, params, json }) => muteIncident(c, c.require(p, "owner"), params[0]!, json.minutes));
r("GET", "/v1/dns/clients", ({ c, p }) => (c.require(p, "owner", "viewer"), dnsClients(c.db, c.now())));
// W16: resolver health (version, checkpoint age, failures, declared gaps) and a manual poll; DK producer authority.
r("GET", "/v1/dns/resolvers", ({ c, p }) => (c.require(p, "owner", "viewer"), c.integrations.resolverStatus()));
r("POST", "/v1/dns/resolvers/:id/poll", ({ c, p, params }) => (c.require(p, "owner"), c.integrations.pollResolver(params[0]!)));
r("GET", "/v1/integrations/digital-kingdom", ({ c, p }) => (c.require(p, "owner", "viewer"), c.integrations.dkStatus()));
r("GET", "/v1/notifications", ({ c, p }) => (c.require(p, "owner"), { destinations: c.notifier.list(), status: c.notifier.status() }));
r("POST", "/v1/notifications/destinations", ({ c, p, json }) => (c.require(p, "owner"), c.notifier.addDestination(json)));
// --- Harness / Dispatch protected-launch contract
r("GET", "/v1/harness/devices/:id/profiles", ({ c, p, params }) => (c.require(p, "owner", "launcher"), c.launchProfiles(params[0]!)));
r("POST", "/v1/harness/devices/:id/sessions/:sid/intent", ({ c, p, params, json }) => c.reportIntent(c.require(p, "owner", "launcher", "agent"), params[0]!, params[1]!, json));
r("POST", "/v1/harness/devices/:id/sessions/:sid/close", ({ c, p, params }) => c.requestClose(c.require(p, "owner", "launcher"), params[0]!, params[1]!));
// --- endpoints (device keys)
r("POST", "/v1/enroll", ({ c, json }) => c.enroll(json));
r("POST", "/v1/device/sync", ({ c, json, req, body }) => {
  const h = req.headers as Record<string, string | undefined>;
  const d = c.authenticateDevice("POST", "/v1/device/sync", h, body);
  return c.sync(d, json as never);
}, true);

const MIME: Record<string, string> = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json", ".webmanifest": "application/manifest+json", ".woff2": "font/woff2" };

export function startServer(c: Controller, opts: { host: string; port: number; webDir?: string | null }): Server {
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://moat.local");
    const send = (status: number, payload: unknown, extra: Record<string, string> = {}) => {
      const body = JSON.stringify(payload);
      const nonce = req.headers["x-moat-nonce"];
      const sig = typeof nonce === "string" && url.pathname.startsWith("/v1/device/") ? c.signResponse(status, nonce, body) : {};
      res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", ...sig, ...extra });
      res.end(body);
    };
    try {
      if (!url.pathname.startsWith("/v1/")) {
        if (opts.webDir && req.method === "GET") {
          const rel = normalize(url.pathname === "/" ? "/index.html" : url.pathname).replace(/^(\.\.[/\\])+/, "");
          const file = join(opts.webDir, rel);
          const target = file.startsWith(opts.webDir) && existsSync(file) && statSync(file).isFile() ? file : join(opts.webDir, "index.html");
          res.writeHead(200, { "content-type": MIME[extname(target)] ?? "application/octet-stream", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:" });
          res.end(readFileSync(target));
          return;
        }
        return send(404, { error: "not found" });
      }
      const route = routes.find((x) => x.method === req.method && x.re.test(url.pathname));
      if (!route) return send(404, { error: "not found" });
      const params = (url.pathname.match(route.re) ?? []).slice(1).map(decodeURIComponent);
      const body = req.method === "GET" ? "" : await readBody(req);
      let json: Record<string, unknown> = {};
      if (body) {
        try {
          json = JSON.parse(body) as Record<string, unknown>;
        } catch {
          throw new HttpError(400, "body must be JSON");
        }
      }
      const auth = req.headers.authorization;
      const p = route.device ? null : c.authenticate(auth?.startsWith("Bearer ") ? auth.slice(7) : undefined);
      const out = await route.h({ c, p, body, json, params, query: url.searchParams, req });
      send(200, out);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : (e as { status?: number }).status ?? 500;
      send(status, { error: status === 500 ? "internal error" : (e as Error).message });
      if (status === 500) console.error(e);
    }
  });
  server.listen(opts.port, opts.host);
  return server;
}
