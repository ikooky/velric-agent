import { chromium, type Page, type Locator } from "playwright-core";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { DEFAULT_HOOK_CONFIG, buildPreloadScript, type HookConfig } from "./preload.js";
import { observeBrowserRequests, type BrowserRequestObservation } from "../application/runtime.js";
import { mergeBrowserSamples, writeOwnedManifest } from "../application/harvest.js";
import { sameOrigin } from "../core/credentials.js";

export interface CoverageInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly hook?: Partial<HookConfig>;
  readonly chromiumPath?: string;
  readonly cookie?: string;
  readonly routes?: string[];
  readonly maxClicksPerCategory?: number;
  readonly timeoutMs?: number;
  readonly proxy?: string;
}
export interface CoverageResult {
  readonly baseUrl: string;
  readonly routesVisited: string[];
  readonly interactions: { route: string; kind: "menu" | "tab" | "table-action" | "toolbar"; label: string; apis: string[]; requestIds?: number[] }[];
  readonly apiLog: string[];
  readonly paramSamples: { path: string; method: string; action: string; query: string; body: string }[];
  readonly requests: BrowserRequestObservation[];
  readonly artifacts: { path: string; bytes: number }[];
  readonly limitations: string[];
}
const UNSAFE = /delete|remove|destroy|drop|logout|signout|uninstall|purge/i;
const dynamic = (row: BrowserRequestObservation): boolean => ["fetch", "xhr"].includes(row.resourceType);
const signature = (row: BrowserRequestObservation): string => JSON.stringify([row.method, row.url, row.reqBody]);

export const runCoverage = async (input: CoverageInput): Promise<CoverageResult> => {
  await ensureDir(input.outputRoot);
  const base = new URL(input.baseUrl);
  const browser = await chromium.launch({ executablePath: input.chromiumPath ?? "/usr/bin/chromium", headless: true,
    args: process.getuid?.() === 0 ? ["--no-sandbox", "--disable-dev-shm-usage"] : ["--disable-dev-shm-usage"], ...(input.proxy ? { proxy: { server: input.proxy } } : {}) });
  try {
    const context = await browser.newContext();
    // This capture scope is one origin. Refuse external navigation and requests
    // instead of allowing cookies (which browsers scope by host, not port) out.
    await context.route("**/*", route => sameOrigin(route.request().url(), base.href) ? route.continue() : route.abort("blockedbyclient"));
    if (input.cookie) await context.addCookies(input.cookie.split(";").map(pair => {
      const i = pair.indexOf("="); return { name: pair.slice(0, i).trim(), value: pair.slice(i + 1).trim(), url: base.origin + "/" };
    }).filter(c => c.name));
    await context.addInitScript(buildPreloadScript({ ...DEFAULT_HOOK_CONFIG, ...input.hook }));
    const page = await context.newPage();
    const observed = observeBrowserRequests(page);
    const routesVisited: string[] = [], interactions: CoverageResult["interactions"] = [], paramSamples: CoverageResult["paramSamples"] = [], limitations: string[] = [];
    const samples = new Map<string, { method: string; url: string; body: string | null; query: string | null; action: string }>();
    const cap = Math.max(0, input.maxClicksPerCategory ?? 8);
    const settle = async (): Promise<void> => { await page.waitForTimeout(300); await observed.drain(); };
    const addSamples = (rows: BrowserRequestObservation[], action: string): void => {
      for (const row of rows.filter(dynamic)) {
        const u = new URL(row.url), key = signature(row);
        if (samples.has(key)) continue;
        samples.set(key, { method: row.method, url: row.url, body: row.reqBody, query: u.search || null, action });
        paramSamples.push({ path: u.pathname, method: row.method, action, query: u.search, body: row.reqBody ?? "" });
      }
    };
    const visit = async (url: string): Promise<boolean> => {
      if (!sameOrigin(url, base.href) || UNSAFE.test(url)) { limitations.push(`route refused: ${url}`); return false; }
      const mark = observed.requests.length;
      try { await page.goto(url, { waitUntil: "domcontentloaded", timeout: input.timeoutMs ?? 30000 }); }
      catch (err) { limitations.push(`navigation: ${String(err).slice(0, 180)}`); }
      await settle();
      if (!sameOrigin(page.url(), base.href)) return false;
      const route = new URL(page.url()).pathname + new URL(page.url()).search;
      if (!routesVisited.includes(route)) routesVisited.push(route);
      addSamples(observed.requests.slice(mark), "first-screen");
      return true;
    };
    const act = async (kind: CoverageResult["interactions"][number]["kind"], label: string, action: () => Promise<unknown>): Promise<void> => {
      const mark = observed.requests.length, route = new URL(page.url()).pathname;
      try { await action(); } catch (err) { limitations.push(`interaction ${label}: ${String(err).slice(0, 100)}`); return; }
      await settle();
      const rows = observed.requests.slice(mark).filter(dynamic);
      interactions.push({ route, kind, label, apis: [...new Set(rows.map(row => `${row.method} ${row.url}`))], requestIds: rows.map(row => row.requestId) });
      addSamples(rows, label);
      if (sameOrigin(page.url(), base.href)) { const landed = new URL(page.url()).pathname; if (!routesVisited.includes(landed)) routesVisited.push(landed); }
    };
    const search = async (): Promise<void> => {
      const box = page.locator("input[type=search], input[placeholder*=搜索 i], input[placeholder*=search i]").first();
      if (!await box.count() || cap === 0) return;
      // Each event is identified across documents; same URL with a new body
      // remains a distinct sample, while repeats merge by method+URL+body.
      const before = new Set(observed.requests.filter(dynamic).map(signature));
      await act("toolbar", "search", async () => { await box.fill("velric"); await box.press("Enter"); });
      addSamples(observed.requests.filter(row => !before.has(signature(row))), "search");
    };
    const clickCategory = async (kind: "tab" | "table-action" | "toolbar", selector: string, onlyAction = false): Promise<void> => {
      const count = Math.min(await page.locator(selector).count(), 40);
      let clicked = 0;
      for (let i = 0; i < count && clicked < cap; i++) {
        const item: Locator = page.locator(selector).nth(i);
        const label = (await item.textContent({ timeout: 1000 }).catch(() => "") ?? "").trim().slice(0, 60);
        if (!label || UNSAFE.test(label) || onlyAction && !/search|query|filter|export|create|new|add|refresh|reload|查看|搜索|筛选|导出|新建|添加|刷新/i.test(label)) continue;
        await act(kind, label, () => item.click({ timeout: 2500 })); clicked++;
      }
    };
    const routes = [...new Set([base.href, ...(input.routes ?? []).map(route => new URL(route, base).href)])].slice(0, 50);
    for (const url of routes) {
      if (!await visit(url)) continue;
      await search();
      await clickCategory("tab", "[role=tab], .ant-tabs-tab, .el-tabs__item");
      await clickCategory("table-action", "table tbody tr:first-child a, table tbody tr:first-child button");
      await clickCategory("toolbar", "button, [role=button]", true);
      const menu = await page.evaluate("[...document.querySelectorAll('nav a, aside a, [class*=sidebar] a, [class*=menu] a')].map(a => ({href:a.href,label:(a.textContent||'').trim()}))") as { href: string; label: string }[];
      for (const m of menu.slice(0, cap)) {
        if (!sameOrigin(m.href, base.href) || UNSAFE.test(m.label) || UNSAFE.test(m.href)) continue;
        await act("menu", m.label, async () => {
          const link = page.locator('a').filter({ hasText: m.label }).first();
          if (await link.count()) await link.click({ timeout: 2500 });
          else await page.goto(m.href, { waitUntil: "domcontentloaded", timeout: input.timeoutMs ?? 30000 });
        });
      }
    }
    await settle();
    observed.close();
    const requests = observed.requests;
    addSamples(requests, "network");
    const apiLog = [...new Set(requests.filter(dynamic).map(row => `${row.method} ${row.url}`))];
    const result: CoverageResult = { baseUrl: input.baseUrl, routesVisited, interactions, apiLog, paramSamples, requests, artifacts: [], limitations };
    result.artifacts.push(await writeArtifact(input.outputRoot, "coverage.json", JSON.stringify({ ...result, mode: input.hook?.mode ?? "passive", limitations: [...limitations, "same-origin capture; external resources blocked"] }, null, 2)));
    result.artifacts.push(await mergeBrowserSamples(input.outputRoot, input.baseUrl, "coverage", [...samples.values()]));
    result.artifacts.push(await writeOwnedManifest(input.outputRoot, "coverage_manifest.json", "coverage", input.baseUrl, result.artifacts, requests.filter(dynamic).length));
    return result;
  } finally { await browser.close(); }
};
