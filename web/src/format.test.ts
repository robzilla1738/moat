import { describe, expect, it } from "vitest";
import { ago, compact, until, COVERAGE } from "./format";
import { demo } from "./data/demo";

describe("format", () => {
  it("relative times", () => {
    const now = Date.parse("2026-10-26T12:00:00Z");
    expect(ago("2026-10-26T11:59:40Z", now)).toBe("just now");
    expect(ago("2026-10-26T11:15:00Z", now)).toBe("45m ago");
    expect(ago("2026-10-26T06:00:00Z", now)).toBe("6h ago");
    expect(until("2026-10-26T12:30:00Z", now)).toBe("30 min left");
    expect(until("2026-10-26T11:00:00Z", now)).toBe("expired");
  });
  it("compact numbers", () => {
    expect(compact(999)).toBe("999");
    expect(compact(3810)).toBe("3.8k");
    expect(compact(18240)).toBe("18k");
  });
});

describe("demo data honesty", () => {
  it("DNS-only devices never claim process, app or byte capabilities", () => {
    for (const d of demo.devices.filter((x) => x.coverage === "dns-only")) {
      expect(d.capabilities.map((c) => c.key)).toEqual(["dns_evidence"]);
    }
    expect(COVERAGE["dns-only"].meaning).toMatch(/can't see apps or connections, or count data/);
  });
  it("macOS devices do not claim protected sessions or proven enforcement", () => {
    for (const d of demo.devices.filter((x) => x.platform === "macos")) {
      expect(d.coverage).not.toBe("protected-session");
      expect(d.capabilities.find((c) => c.key === "session_enforcement")?.support).toBe("unsupported");
    }
  });
  it("instrumented sessions are not marked verified", () => {
    for (const s of demo.sessions.filter((x) => x.boundaryKind === "instrumented_only")) expect(s.verified).toBe(false);
  });
  it("blocked-at-connect incidents never claim byte counts", () => {
    for (const i of demo.incidents.filter((x) => x.measurement.startsWith("Blocked at connect"))) expect(i.measurement).not.toMatch(/\d+ ?(B|KB|MB)/);
  });
});
