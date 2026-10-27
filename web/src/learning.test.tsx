/**
 * W14 review screens: nothing is accepted by default, incomplete evidence needs an explicit acknowledgement, unknown
 * identity and gaps stay visible, the drift queue is separate, and the pack browser shows unsupported cells.
 */
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { StoreProvider } from "./data/store";
import { demo } from "./data/demo";
import { acceptBody, demoLearning, demoPacks, gapKind } from "./data/learning";
import { CandidateReview, Learning, Packs } from "./screens/Learning";
import type { ReactNode } from "react";

const inDemo = (node: ReactNode) => renderToStaticMarkup(<StoreProvider options={{ initial: { mode: "demo", data: { ...demo } } }}>{node}</StoreProvider>);
const go = () => {};

describe("accept request", () => {
  const cand = demoLearning.review_queue[0]!;
  it("accepts nothing by default", () => {
    expect(acceptBody(cand, [], true)).toEqual({ refusal: expect.stringMatching(/Nothing is accepted by default/) });
  });
  it("needs an explicit acknowledgement when the evidence is incomplete", () => {
    expect(cand.completeness).toBe("incomplete");
    expect(acceptBody(cand, [0], false)).toEqual({ refusal: expect.stringMatching(/incomplete/) });
    expect(acceptBody(cand, [0, 0, 99, -1], true)).toEqual({ accept: [0], acknowledge_incomplete: true });
  });
  it("does not send an acknowledgement for complete evidence", () => {
    expect(acceptBody({ ...cand, completeness: "complete" }, [1, 0], true)).toEqual({ accept: [0, 1], acknowledge_incomplete: false });
  });
  it("classifies gap reasons so unknown identity is never just a gap", () => {
    expect(gapKind("3 connection(s) in the window had no executable identity and cannot be attributed")).toBe("identity");
    expect(gapKind("events 4–9 were lost on or before delivery")).toBe("lost");
    expect(gapKind("events after #3 have not all arrived yet")).toBe("pending");
  });
});

describe("candidate review", () => {
  const html = inDemo(<CandidateReview id="cand-demo-1" go={go} />);
  it("shows the permission diff with every entry unselected", () => {
    expect(html).toContain("Permission diff");
    expect(html).toContain("4 would broaden");
    expect(html).toContain("registry.npmjs.org");
    expect(html).not.toMatch(/type="checkbox"[^>]*checked/);
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Accept/);
  });
  it("keeps unknown identity, lost events and refused-only entries visible", () => {
    expect(html).toContain("unknown identity");
    expect(html).toContain("lost events");
    expect(html).toContain("Only ever refused");
    expect(html).toContain("Destination not reported");
  });
  it("says accepting needs the owner and enforcing needs the owner key", () => {
    expect(html).toContain("needs an owner sign-in");
    expect(html).toContain("your owner key must sign");
  });
});

describe("learning overview and drift queue", () => {
  const html = inDemo(<Learning go={go} />);
  it("has a bounded capture control and separate review and drift queues", () => {
    expect(html).toContain("Capture a workflow");
    expect(html).toContain("Existing rules, including every deny, stay enforced");
    expect(html).toContain("Candidates");
    expect(html).toContain("Drift review");
    expect(html).toContain("1 in queue");
    expect(html).toContain("Reviewed baselines");
  });
});

describe("pack browser", () => {
  const html = inDemo(<Packs />);
  it("shows each module's effective delta and the cells where it would not take effect", () => {
    expect(html).toContain("unsupported cells");
    expect(html).toContain(String(demoPacks[0]!.effective.unsupported_cells));
    expect(html).toContain("skipped with a report: session enforcement unsupported");
    expect(html).toContain("Already in the current policy: no change.");
    expect(html).toContain("api.anthropic.com");
  });
  it("enables nothing by default", () => {
    expect(html).not.toMatch(/type="checkbox"[^>]*checked/);
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Propose/);
  });
});
