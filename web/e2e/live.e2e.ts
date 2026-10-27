/**
 * Browser integration tests against the real controller API (W08). The page is the production build; the controller,
 * signer, moatctl and endpoint protocol are real. Run: `npm run e2e -w web` after `vite build --outDir build/live`.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser, type Page } from "playwright";
import { startHarness, type Harness } from "../../controller/test/live-harness.ts";

const WEB = resolve(dirname(fileURLToPath(import.meta.url)), "../build/live");
let h: Harness;
let browser: Browser;
let seq = 0;
const dialogs: string[] = [];
const SHOTS = process.env.MOAT_SCREENSHOT_DIR;
/** Evidence screenshots of the real live UI (CI uploads them; docs/screenshots keeps reviewed copies). */
async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` });
}

const at = () => new Date().toISOString();
function blockedFlow(session: string, ip: string, port: number, app = "curl", hostname?: string) {
  return { seq: ++seq, at: at(), event: { type: "flow", attempt: { id: `f${seq}`, device_id: "omarchy", app: { family: app, executable: `/usr/bin/${app}` }, remote_ip: ip, remote_port: port, transport: "tcp", at: at(), hostname: hostname ? { name: hostname } : undefined, session: { id: session, profile: "coding-session", boundary: "linux_cgroup", verified: true }, process: { device_id: "omarchy", boot_id: "b", pid: 4000 + seq, start_generation: seq } }, decision: { verdict: "deny", profile: "coding-session", policy_revision: 1 }, chain: ["claude", "zsh", app] } };
}
function sessionStarted(id: string) {
  return { seq: ++seq, at: at(), event: { type: "session_started", session_id: id, profile: "coding-session", cgroup: `moat.slice/s-${id}`, uid: 1000, root_pid: 4242, root_start: 1, boundary: "linux_cgroup" } };
}

async function signedIn(token: string): Promise<Page> {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  page.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await page.goto(h.url + "/");
  await page.getByLabel("Access token").fill(token);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("Needs a decision").or(page.getByText("All quiet.")).first().waitFor();
  return page;
}

before(async () => {
  h = await startHarness(WEB);
  browser = await chromium.launch();
  h.c.notifier.addDestination({ name: "phone", kind: "ntfy", url: "https://ntfy.example/moat", min_urgency: "low" });
  await h.sync({ last_applied: 1, receipts: [{ revision: 1, state: "applied" }], events: [sessionStarted("20261027-aaaa"), blockedFlow("20261027-aaaa", "203.0.113.50", 443)] });
});
after(async () => {
  await browser?.close();
  await h?.stop();
});

test("signed out: the live UI asks for a sign-in and never shows sample data", async () => {
  const page = await browser.newPage();
  await page.goto(h.url + "/");
  await page.getByText("Sign in to your controller").waitFor();
  await shot(page, "live-sign-in");
  assert.equal(await page.getByText("MacBook Air").count(), 0);
  await page.getByLabel("Access token").fill("moat_owner_wrong");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("did not accept this sign-in").waitFor();
  assert.equal(await page.getByText("Living room TV").count(), 0, "a rejected token never falls back to demo data");
  await page.close();
});

test("allow once: exact plan, phone approval with a delegated key, pending until the endpoint's receipt, then active", async () => {
  const page = await signedIn(h.ownerToken);
  let card = page.locator(".decision").filter({ hasText: "203.0.113.50" }).first();
  await card.getByRole("button", { name: "Allow once for this session" }).click();
  // the plan is rendered from the controller's canonical record
  await card.getByText("review: not approved yet").waitFor();
  await card.getByText("20261027-aaaa").waitFor();
  await card.getByText("TCP 443").first().waitFor();
  await card.getByText("retries keep this deadline").waitFor();
  await shot(page, "live-allow-once-review");
  // an owner bearer token alone is not enough for this signer
  await card.getByRole("button", { name: "Approve exactly this" }).click();
  await card.getByText(/only accepts phone approvals from a delegated key/).waitFor();
  assert.equal(((await h.owner("GET", "/v1/grants")).json as unknown as unknown[]).length, 0, "nothing was granted");
  // set up this browser as a delegated approver: its own key, an owner-signed delegation made off the page
  await page.goto(`${h.url}/#/devices`);
  await page.getByRole("button", { name: "Create an approval key for this device" }).click();
  const cmd = await page.locator(".approvals pre.code").textContent();
  const pub = /delegate-issuer <owner\.key> ([0-9a-f]{64})/.exec(cmd ?? "")![1]!;
  await page.getByLabel("Paste the printed delegation").fill(h.delegate(pub, ["omarchy"]));
  await page.getByRole("button", { name: "Use this delegation" }).click();
  await page.locator(".approvals").getByText("delegated", { exact: true }).waitFor();
  await shot(page, "live-phone-approvals");
  await page.goto(`${h.url}/#/`);
  card = page.locator(".decision").filter({ hasText: "203.0.113.50" }).first();
  await card.getByRole("button", { name: "Allow once for this session" }).click();
  await card.getByText(/Signed on this device with its delegated approval key/).waitFor();
  await card.getByRole("button", { name: "Approve exactly this" }).click();
  await card.getByText("pending: no endpoint receipt yet").waitFor();
  await card.getByText("Signed as revision 2").waitFor();
  await card.getByText("authorized by a delegated approval key").waitFor();
  assert.equal(await card.getByText("active on the endpoint").count(), 0, "a signed revision is not an applied one");
  await shot(page, "live-allow-once-pending");
  // the endpoint syncs: delivery, then still not applied
  await h.sync({ last_applied: 1 });
  await card.getByText("Delivered to omarchy").waitFor();
  await page.waitForTimeout(3500);
  assert.equal(await card.getByText("active on the endpoint").count(), 0, "delivery is not application");
  // the endpoint applies revision 2 and says so
  await h.sync({ last_applied: 2, receipts: [{ revision: 2, state: "applied" }] });
  await card.getByText("active on the endpoint").waitFor({ timeout: 10_000 });
  await card.getByText("endpoint receipt for revision 2").waitFor();
  await shot(page, "live-allow-once-active");
  const grants = (await h.owner("GET", "/v1/grants")).json as unknown as { state: string; device_id: string; authorized_by: string }[];
  assert.equal(grants[0]!.state, "active");
  assert.equal(grants[0]!.device_id, "omarchy");
  assert.equal(grants[0]!.authorized_by, "delegated_issuer");
  await page.close();
});

test("a stale view is refused, not applied: precondition on incident and policy revision", async () => {
  await h.sync({ events: [sessionStarted("20261027-bbbb"), blockedFlow("20261027-bbbb", "198.51.100.7", 8443)] });
  const page = await signedIn(h.ownerToken);
  const card = page.locator(".decision").filter({ hasText: "198.51.100.7" }).first();
  await card.waitFor();
  // policy moves behind the page's back (another owner action)
  const inc = ((await h.owner("GET", "/v1/incidents")).json as unknown as { id: string; destination: string; revision: number }[]).find((i) => i.destination === "203.0.113.50")!;
  await h.c.revokeGrant(h.c.authenticate(h.ownerToken)!, (h.c.grants()[0] as { id: string }).id);
  // (the page still shows policy revision 2)
  void inc;
  await card.getByRole("button", { name: "Allow once for this session" }).click();
  await card.getByText(/Refused as stale/).first().waitFor();
  await shot(page, "live-stale-refused");
  assert.equal(await card.getByText("active on the endpoint").count(), 0);
  await page.close();
});

test("a notification reference opens exactly its incident, even after reordering; unknown references open nothing", async () => {
  const first = ((await h.owner("GET", "/v1/incidents")).json as unknown as { id: string; destination: string }[]).find((i) => i.destination === "203.0.113.50")!;
  const ref = (h.c.db.prepare("SELECT opaque_ref FROM notify_outbox WHERE incident_id = ? LIMIT 1").get(first.id) as { opaque_ref: string }).opaque_ref;
  // newer incidents push it down the list
  for (let i = 0; i < 4; i++) await h.sync({ events: [sessionStarted(`20261027-c00${i}`), blockedFlow(`20261027-c00${i}`, `192.0.2.${10 + i}`, 443)] });
  const page = await signedIn(h.ownerToken);
  await page.goto(`${h.url}/#/r/${ref}`);
  await page.waitForURL(new RegExp(`#/activity/${first.id}$`));
  await page.locator("h1").getByText("203.0.113.50").waitFor();
  await page.goto(`${h.url}/#/r/AAAAAAAAAAAAAAAA`);
  await page.getByText("Notification not found").waitFor();
  await shot(page, "live-unknown-reference");
  assert.equal(await page.locator(".decision").count(), 0, "no other incident is substituted");
  await page.close();
});

test("a viewer sees disabled owner actions with the reason", async () => {
  const page = await signedIn(h.viewerToken);
  const btn = page.getByRole("button", { name: "Allow once for this session" }).first();
  assert.equal(await btn.isDisabled(), true);
  await page.getByText(/Signed in as viewer: read only/).first().waitFor();
  await shot(page, "live-viewer-read-only");
  await page.close();
});

test("hostile names and destinations render as inert text with a visible warning", async () => {
  await h.sync({ events: [sessionStarted("20261027-dddd"), blockedFlow("20261027-dddd", "192.0.2.99", 443, '<img src=x onerror="alert(1)">', "github.com\u202Emoc.evil")] });
  const page = await signedIn(h.ownerToken);
  await page.goto(`${h.url}/#/activity`);
  await page.getByRole("tab", { name: "All" }).click();
  await page.getByText("⟨U+202E⟩").first().waitFor();
  await page.getByText("contains direction-changing characters").first().waitFor();
  await shot(page, "live-hostile-identifiers");
  assert.equal(await page.locator("img[src=x]").count(), 0);
  assert.deepEqual(dialogs, [], "no injected script ran");
  await page.close();
});

test("controller outage: the page says it is not current and pauses actions; no sample data appears", async () => {
  const page = await signedIn(h.ownerToken);
  await page.route("**/v1/**", (r) => r.abort("connectionrefused"));
  await page.getByText("Not current.").waitFor({ timeout: 20_000 });
  await shot(page, "live-controller-unreachable");
  const btn = page.getByRole("button", { name: "Allow once for this session" }).first();
  if (await btn.count()) assert.equal(await btn.isDisabled(), true);
  assert.equal(await page.getByText("Living room TV").count(), 0);
  await page.close();
});
