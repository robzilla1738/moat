/**
 * W08 regression tests: hostile and confusing display data, consumer-computed freshness, evidence-only action
 * states and explicit demo/live separation.
 */
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { inspectIdent } from "./data/ident";
import { deviceFreshness, evidenceAgeMs, STALE_AFTER_MS } from "./data/freshness";
import { grantSteps, StoreProvider } from "./data/store";
import { ApiError, loadLive, mapApp, mapIncident, makeApi, type Api, type WireIncident } from "./data/api";
import { DecisionCard, IncidentDetail, allowOnceUnavailable } from "./screens/Activity";
import { App } from "./App";
import type { Incident, Snapshot } from "./data/types";
import { demo } from "./data/demo";

const T0 = "2026-10-27T15:00:00.000Z";

function liveSnap(over: Partial<Snapshot> = {}): Snapshot {
  return { generatedAt: T0, serverTime: T0, fetchedAt: T0, demo: false, viewer: { name: "robert", role: "owner" }, policyRevision: 3, devices: [{ id: "omarchy", name: "Omarchy", model: "linux", platform: "linux", coverage: "enforced", coverageNote: "", lastSeen: T0, revision: 3, revisionState: "applied", capabilities: [], telemetryGaps: [], blockedToday: 0, flowsToday: 0 }], incidents: [], sessions: [], apps: [], revisions: [], simulation: null, timeline: [], grants: [], ...over };
}

const hostile: Incident = {
  id: "inc_<script>",
  revision: 4,
  kind: "blocked_connection",
  urgency: "high",
  state: "open",
  deviceId: "omarchy",
  sessionId: "20261027-abcd",
  app: '<img src=x onerror="alert(1)">',
  destination: "github.com\u202Emoc.live",
  port: 443,
  protocol: "TCP 443",
  reason: "blocked by default:coding-session",
  explanation: "</p><script>fetch('/v1/grants',{method:'POST'})</script>",
  measurement: "",
  facts: [{ label: "Rule", value: "default:\u200Bcoding" }],
  occurrences: 1,
  firstAt: T0,
  lastAt: T0,
};

const noApi: Api = { get: async () => Promise.reject(new ApiError(0, "offline")), post: async () => Promise.reject(new ApiError(0, "offline")) };

describe("untrusted identifiers", () => {
  it("makes direction overrides, zero-width and control characters visible", () => {
    const r = inspectIdent("github.com\u202Emoc.live", { kind: "host" });
    expect(r.text).toContain("⟨U+202E⟩");
    expect(r.warnings.join()).toMatch(/direction/);
    expect(inspectIdent("pay\u200Bpal.com", { kind: "host" }).text).toBe("pay⟨U+200B⟩pal.com");
    expect(inspectIdent("a\u0000b").text).toBe("a⟨U+0000⟩b");
    expect(inspectIdent("line1\nline2").warnings).toContain("contains line breaks");
  });
  it("flags look-alike scripts and punycode", () => {
    expect(inspectIdent("gіthub.com", { kind: "host" }).warnings.join()).toMatch(/Latin and Cyrillic/); // Cyrillic і
    expect(inspectIdent("xn--githb-n2a.com", { kind: "host" }).warnings.join()).toMatch(/punycode/);
    expect(inspectIdent("github.com", { kind: "host" }).warnings).toEqual([]);
  });
  it("shortens absurd values and says so", () => {
    const r = inspectIdent("a".repeat(5000));
    expect([...r.text].length).toBeLessThan(200);
    expect(r.warnings.join()).toMatch(/shortened from 5000/);
  });
  it("renders hostile incident fields as text, never markup", () => {
    const html = renderToStaticMarkup(
      <StoreProvider options={{ initial: { mode: "live", data: liveSnap({ incidents: [hostile] }), status: "ready" }, api: noApi }}>
        <DecisionCard incident={hostile} go={() => {}} detailed />
        <IncidentDetail id={hostile.id} go={() => {}} />
      </StoreProvider>,
    );
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<img/i);
    expect(html).toContain("&lt;img src=x");
    expect(html).toContain("⟨U+202E⟩");
    expect(html).toContain("⟨U+200B⟩");
    expect(html).toMatch(/direction-changing/);
  });
});

describe("freshness is computed by the consumer", () => {
  const d = liveSnap().devices[0]!;
  it("an old report labeled healthy is shown as unknown, not its label", () => {
    const old = { ...d, lastSeen: new Date(Date.parse(T0) - STALE_AFTER_MS - 60_000).toISOString() };
    const f = deviceFreshness(old, { serverTime: T0, fetchedAt: T0 }, Date.parse(T0));
    expect(f.coverage).toBe("unknown");
    expect(f.stale).toBe(true);
    expect(f.note).toMatch(/not current evidence/);
  });
  it("a never-reporting device is unknown", () => {
    expect(deviceFreshness({ ...d, lastSeen: null }, { serverTime: T0, fetchedAt: T0 }).coverage).toBe("unknown");
  });
  it("uses the controller clock: a browser clock far in the past cannot make old evidence fresh", () => {
    const old = new Date(Date.parse(T0) - 3600_000).toISOString();
    const browserNow = Date.parse(T0) - 7200_000; // browser two hours behind
    expect(deviceFreshness({ ...d, lastSeen: old }, { serverTime: T0, fetchedAt: new Date(browserNow).toISOString() }, browserNow).stale).toBe(true);
  });
  it("holding a snapshot ages its evidence", () => {
    expect(evidenceAgeMs(T0, { serverTime: T0, fetchedAt: T0 }, Date.parse(T0) + 11 * 60_000)).toBe(11 * 60_000);
    expect(deviceFreshness(d, { serverTime: T0, fetchedAt: T0 }, Date.parse(T0) + 11 * 60_000).coverage).toBe("unknown");
  });
});

describe("action states come from evidence", () => {
  const base = { id: "grant-1", revision: 4, authorized_by: "temporary_grant_overlay", expires_at: T0, server_time: T0 };
  it("pending: nothing claims applied", () => {
    const a = grantSteps({ ...base, state: "pending", devices: [{ device_id: "omarchy", state: "delivered", stale: false, evidence: null }] }, () => "Omarchy");
    expect(a.phase).toBe("pending");
    expect(a.steps.find((s) => s.label.startsWith("Applied"))!.state).toBe("pending");
  });
  it("active needs an endpoint receipt and names it", () => {
    const a = grantSteps({ ...base, state: "active", devices: [{ device_id: "omarchy", state: "applied", stale: false, evidence: { revision: 4, state: "applied", at: T0, detail: null } }] }, () => "Omarchy");
    expect(a.phase).toBe("active");
    expect(a.steps.find((s) => s.label === "Applied by Omarchy")!.detail).toMatch(/receipt for revision 4/);
  });
  it("rejected shows the device's rejection", () => {
    const a = grantSteps({ ...base, state: "rejected", devices: [{ device_id: "omarchy", state: "rejected", stale: false, evidence: { revision: 4, state: "rejected", at: T0, detail: "compile failed" } }] }, () => "Omarchy");
    expect(a.phase).toBe("rejected");
    expect(a.steps.some((s) => s.state === "failed" && s.detail === "compile failed")).toBe(true);
  });
  it("authorizer shown comes from the controller, not a constant", () => {
    expect(grantSteps({ ...base, authorized_by: null, state: "pending", devices: [] }, () => "x").steps[1]!.detail).toBe("authorizer not recorded");
  });
  it("unfinished actions are disabled with a reason", () => {
    expect(allowOnceUnavailable({ ...hostile, sessionId: undefined })).toMatch(/W03\/W07/);
    expect(allowOnceUnavailable({ ...hostile, destination: "rule-scoped", port: undefined })).toMatch(/rule-scoped/);
    const html = renderToStaticMarkup(
      <StoreProvider options={{ initial: { mode: "live", data: liveSnap({ viewer: { name: "tv", role: "viewer" }, incidents: [hostile] }), status: "ready" }, api: noApi }}>
        <DecisionCard incident={hostile} go={() => {}} />
      </StoreProvider>,
    );
    expect(html).toMatch(/disabled=""[^>]*>.*Allow once/s);
    expect(html).toMatch(/read only/);
  });
});

describe("demo and live are separate", () => {
  it("live mode without a session shows sign-in, never sample data", () => {
    const html = renderToStaticMarkup(
      <StoreProvider options={{ initial: { mode: "live", status: "signed_out" } }}>
        <App />
      </StoreProvider>,
    );
    expect(html).toMatch(/Sign in to your controller/);
    expect(html).not.toContain(demo.devices[0]!.name);
  });
  it("an unreachable controller with no data shows the failure, not sample data", () => {
    const html = renderToStaticMarkup(
      <StoreProvider options={{ initial: { mode: "live", status: "unreachable" }, api: noApi }}>
        <App />
      </StoreProvider>,
    );
    expect(html).toMatch(/Can(&#x27;|')t reach the controller/);
    expect(html).not.toContain(demo.devices[0]!.name);
  });
  it("demo mode is labeled on every screen", () => {
    const html = renderToStaticMarkup(
      <StoreProvider options={{ initial: { mode: "demo", data: demo, status: "ready" } }}>
        <App />
      </StoreProvider>,
    );
    expect(html).toMatch(/Sample data\./);
  });
  it("the live loader keeps absent data empty instead of borrowing sample data", async () => {
    const replies: Record<string, unknown> = {
      "/v1/me": { id: "t", name: "robert", role: "owner" },
      "/v1/overview": { server_time: T0, revision: 2 },
      "/v1/devices": [],
      "/v1/incidents": [],
      "/v1/policy/revisions": [],
      "/v1/sessions": [],
      "/v1/grants": [],
      "/v1/apps": [],
      "/v1/reconciliation": [],
    };
    const api: Api = { get: async (p) => (p.startsWith("/v1/rollups") ? [] : replies[p]) as never, post: async () => ({}) as never };
    const s = await loadLive(api, () => new Date(T0));
    expect(s.demo).toBe(false);
    expect(s.simulation).toBeNull();
    expect(s.apps).toEqual([]);
    expect(s.serverTime).toBe(T0);
  });
  it("live apps are executable identities with evidence counts; unknown identity is never labeled enforced", () => {
    const known = mapApp({ id: "app-1", name: "curl", family: "curl", exe: "/usr/bin/curl", signer: null, identity: "executable", devices: ["mbp"], sessions: 0, flows: 3, denied: 1, observed: 2, destinations: [{ host: "example.org", port: 443, count: 3, verdict: "deny", firstAt: T0, lastAt: T0, new: true }], lastActive: T0, firstSeen: T0 });
    expect(known.enforcement).toBe("evidence");
    expect(known.signing).toBe("no signing identity reported");
    expect(known.destinations[0]).toEqual({ host: "example.org:443", count: 3, verdict: "deny", firstSeen: true });
    const unknown = mapApp({ id: "unknown-identity", name: "Identity unknown", family: null, exe: null, signer: null, identity: "unknown", devices: ["mbp"], sessions: 0, flows: 1, denied: 0, observed: 1, destinations: [], lastActive: T0, firstSeen: T0 });
    expect(unknown.identity).toBe("unknown");
    expect(unknown.exe).toBe("executable not recorded");
  });
  it("network failures are errors with status 0, not data", async () => {
    const api = makeApi("t", (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch);
    await expect(api.get("/v1/overview")).rejects.toMatchObject({ status: 0 });
  });
  it("maps controller incidents without inventing measurements", () => {
    const w: WireIncident = { id: "inc_1", revision: 1, kind: "blocked_connection", urgency: "medium", state: "open", device_id: "omarchy", session_id: null, process_instance: null, app: null, destination: "rule-scoped", port: null, transport: null, reason: "3 packet(s) rejected", rule: "default:x", policy_revision: 1, occurrences: 1, first_at: T0, last_at: T0, facts: {} };
    expect(mapIncident(w).measurement).toMatch(/No transfer measurement/);
  });
});

describe("device-targeted snapshots (issue #26)", () => {
  it("a device the current snapshot does not name says so instead of showing the revision as its own", async () => {
    const { mapDevice } = await import("./data/api");
    const base = { id: "linux-2", name: "Linux 2", platform: "linux", coverage: null, last_seen_at: null, last_revision: null, telemetry_gaps: [] as [number, number][], capabilities: null, status: null, revision_states: [{ revision: 4, state: "not_targeted", at: "x", detail: "compiled for omarchy" }] };
    const d = mapDevice({ ...base, awaiting_retarget: true });
    expect(d.awaitingRetarget).toBe(true);
    expect(d.revisionState).toBe("not_targeted");
    expect(mapDevice(base).awaitingRetarget).toBe(false);
  });
});
