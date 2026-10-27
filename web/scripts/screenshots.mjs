// Render the demo build to PNGs and check every rendered page for horizontal overflow, clipped text and WCAG AA
// colour contrast (axe-core), in dark and light, with and without reduced transparency.
//
//   npm run build:demo -w web && node web/scripts/screenshots.mjs <out-dir> [more out-dirs...]
//
// CHROMIUM_PATH selects a browser binary (otherwise Playwright's own). Exits non-zero on overflow or contrast
// violations so CI keeps the UI honest.
import { createServer } from "node:http";
import { readFile, mkdir, copyFile } from "node:fs/promises";
import { extname, join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, "../dist");
const outs = process.argv.slice(2).map((d) => resolve(d));
if (!outs.length) {
  console.error("usage: screenshots.mjs <out-dir> [...]");
  process.exit(2);
}
const axeSource = await readFile(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");

const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".webmanifest": "application/manifest+json", ".png": "image/png" };
const server = createServer(async (req, res) => {
  const path = decodeURIComponent((req.url ?? "/").split("?")[0]);
  const file = join(dist, path === "/" ? "index.html" : path);
  try {
    const body = await readFile(file);
    res.writeHead(200, { "content-type": types[extname(file)] ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}/`;

const phone = { width: 390, height: 844, deviceScaleFactor: 3, isMobile: true, hasTouch: true };
const desktop = { width: 1440, height: 900, deviceScaleFactor: 2 };
const shots = [
  { name: "mobile-home-dark", hash: "", theme: "dark", vp: phone },
  { name: "mobile-home-light", hash: "", theme: "light", vp: phone },
  { name: "mobile-activity-light", hash: "activity", theme: "light", vp: phone },
  { name: "mobile-allow-once-dark", hash: "activity/inc-8f2a", theme: "dark", vp: phone },
  { name: "mobile-coverage-dark", hash: "coverage", theme: "dark", vp: phone },
  { name: "mobile-device-dns-dark", hash: "devices/tcl-tv", theme: "dark", vp: phone },
  { name: "mobile-home-reduced-transparency-light", hash: "", theme: "light", vp: phone, reduceTransparency: true },
  { name: "desktop-home-light", hash: "", theme: "light", vp: desktop },
  { name: "desktop-home-dark", hash: "", theme: "dark", vp: desktop },
  { name: "desktop-rules-dark", hash: "rules", theme: "dark", vp: desktop },
  { name: "desktop-activity-dark", hash: "activity", theme: "dark", vp: desktop },
  { name: "mobile-learning-candidate-dark", hash: "learning/c/cand-demo-1", theme: "dark", vp: phone },
  { name: "mobile-learning-light", hash: "learning", theme: "light", vp: phone },
  { name: "desktop-packs-dark", hash: "learning/packs", theme: "dark", vp: desktop },
  { name: "desktop-learning-drift-light", hash: "learning/c/cand-demo-2", theme: "light", vp: desktop },
];
// Every route is also checked (no screenshot) in both themes at phone size.
const routes = ["", "activity", "activity/inc-8f2a", "activity/inc-7c31", "sessions", "rules", "devices", "devices/omarchy", "devices/tcl-tv", "apps", "coverage", "learning", "learning/c/cand-demo-1", "learning/c/cand-demo-2", "learning/b/base-demo-1", "learning/packs"];

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, args: ["--font-render-hinting=none"] });
const problems = [];

async function open(vp, theme, hash, reduceTransparency = false) {
  const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, deviceScaleFactor: vp.deviceScaleFactor, isMobile: !!vp.isMobile, hasTouch: !!vp.hasTouch, colorScheme: theme, reducedMotion: "reduce" });
  await ctx.addInitScript((t) => localStorage.setItem("moat.theme", t), theme);
  const page = await ctx.newPage();
  if (reduceTransparency) {
    const cdp = await ctx.newCDPSession(page);
    await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-transparency", value: "reduce" }] });
  }
  await page.goto(`${base}#/${hash}`, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);
  return { ctx, page };
}

async function check(page, label) {
  const r = await page.evaluate(() => {
    const doc = document.documentElement;
    const overflowX = doc.scrollWidth - window.innerWidth;
    const clipped = [];
    for (const el of document.querySelectorAll("body *")) {
      const cs = getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden" || !el.childNodes.length) continue;
      const hasText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
      if (!hasText) continue;
      const intended = cs.textOverflow === "ellipsis" || el.closest(".ellipsis, .matrix-scroll, .device-strip, .segmented, .subnav");
      if (!intended && (cs.overflowX === "hidden" || cs.overflow === "hidden") && el.scrollWidth > el.clientWidth + 1) {
        clipped.push(`${el.tagName.toLowerCase()}.${[...el.classList].join(".")}: "${el.textContent.trim().slice(0, 40)}"`);
      }
    }
    return { overflowX, clipped };
  });
  if (r.overflowX > 1) problems.push(`${label}: page overflows horizontally by ${r.overflowX}px`);
  for (const c of r.clipped) problems.push(`${label}: clipped text ${c}`);
  await page.addScriptTag({ content: axeSource });
  const axe = await page.evaluate(async () => {
    // eslint-disable-next-line no-undef
    const res = await axe.run(document, { runOnly: { type: "rule", values: ["color-contrast"] } });
    return res.violations.flatMap((v) => v.nodes.map((n) => `${n.target.join(" ")} — ${n.any.map((a) => a.message).join("; ")}`));
  });
  for (const a of axe) problems.push(`${label}: contrast ${a}`);
}

for (const s of shots) {
  const { ctx, page } = await open(s.vp, s.theme, s.hash, s.reduceTransparency);
  await check(page, s.name);
  const first = join(outs[0], `${s.name}.png`);
  await mkdir(outs[0], { recursive: true });
  await page.screenshot({ path: first });
  for (const o of outs.slice(1)) {
    await mkdir(o, { recursive: true });
    await copyFile(first, join(o, `${s.name}.png`));
  }
  console.log(`shot ${s.name}`);
  await ctx.close();
}
for (const theme of ["dark", "light"]) {
  for (const hash of routes) {
    const { ctx, page } = await open(phone, theme, hash);
    await check(page, `phone ${theme} #/${hash}`);
    await ctx.close();
  }
}
await browser.close();
server.close();
if (problems.length) {
  console.error(`\n${problems.length} problem(s):\n` + problems.map((p) => `  - ${p}`).join("\n"));
  process.exit(1);
}
console.log(`\nall ${shots.length} screenshots and ${routes.length * 2} route checks passed (no overflow, no clipped text, no AA contrast violations)`);
