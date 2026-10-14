import { chromium } from "playwright-core";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { buildPreloadScript, type HookConfig } from "./preload.js";

/** Coverage mode (api-recon Phase 3b): drive a real browser through the
 *  discovered UI surface — sidebar menu items, tabs, table row actions,
 *  toolbar buttons — recording every outbound request per interaction.
 *  Repeats each module's list-first-screen vs search vs filter vs create
 *  actions to build the parameter trigger matrix (multi-sample diff). */

export interface CoverageInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly hook?: Partial<HookConfig>;
  readonly chromiumPath?: string;
  readonly cookie?: string;
  readonly routes?: string[];
  /** Max interactive elements clicked per category. */
  readonly maxClicksPerCategory?: number;
  readonly timeoutMs?: number;
  readonly proxy?: string;
}

export interface CoverageResult {
  readonly baseUrl: string;
  readonly routesVisited: string[];
  readonly interactions: { route: string; kind: "menu" | "tab" | "table-action" | "toolbar"; label: string; apis: string[] }[];
  readonly apiLog: string[];
  readonly paramSamples: { path: string; method: string; action: string; query: string; body: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const SAFE_LABEL_RE = /delete|remove|destroy|drop|logout|signout|uninstall|purge/i;

export const runCoverage = async (input: CoverageInput): Promise<CoverageResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const hook: HookConfig = {
    apiPattern: "/api/|/rest/|/graphql",
    loginPathRe: "^/(login|signin)",
    recordDetail: true,
    stubs: [],
    neutralize: { fields: ["code", "response_code", "errno", "ret"], success: 0 },
    neutralizeVueRouter: true,
    recordSse: true,
    ...input.hook,
  } as HookConfig;
  const preload = buildPreloadScript(hook);

  const browser = await chromium.launch({
    executablePath: input.chromiumPath ?? "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const context = await browser.newContext();
    if (input.cookie) {
      const u = new URL(input.baseUrl);
      for (const pair of input.cookie.split(";").map((p) => p.trim()).filter(Boolean)) {
        const [name, ...rest] = pair.split("=");
        await context.addCookies([{ name: name!, value: rest.join("="), domain: u.hostname, path: "/" }]);
      }
    }
    await context.addInitScript(preload);
    const page = await context.newPage();
    await page.goto(input.baseUrl, { waitUntil: "domcontentloaded", timeout: input.timeoutMs ?? 45000 });
    await page.waitForTimeout(2000);

    const readLog = (): Promise<string[]> => page.evaluate("[...(window.__API_RECON_LOG__ || [])]");
    const mark = async (): Promise<number> => (await page.evaluate("(window.__API_RECON_DETAIL__ || []).length")) as number;
    const since = async (n: number): Promise<string[]> =>
      ((await page.evaluate("(window.__API_RECON_DETAIL__ || []).slice(" + n + ").map(function(e){return ((e.method || 'GET').toUpperCase() + ' ' + e.url)})")) as string[]);
    const routesVisited: string[] = ["/"];
    const interactions: CoverageResult["interactions"] = [];
    const paramSamples: CoverageResult["paramSamples"] = [];
    const cap = input.maxClicksPerCategory ?? 8;

    // ---- menu: sidebar links ----
    const menuLabels = (await page.evaluate(`[...document.querySelectorAll('nav a, aside a, [class*=sidebar] a, [class*=menu] a')]
      .map(function(a){ return { text: (a.textContent || '').trim().slice(0, 40), href: a.getAttribute('href') } })
      .filter(function(x){ return x.href && x.href.startsWith('/') && x.text.length > 0 })
      .slice(0, 20)`)) as { text: string; href: string }[];
    for (const m of menuLabels) {
      if (SAFE_LABEL_RE.test(m.text!) || SAFE_LABEL_RE.test(m.href!)) continue;
      // Try in-page click first (SPA pushState keeps the preload log); fall
      // back to full navigation for MPA-style links.
      const before = await mark();
      let clicked = false;
      try {
        const link = page.locator(`a[href="${m.href}"]`).first();
        if ((await link.count()) > 0) {
          await link.click({ timeout: 4000 });
          clicked = true;
        }
      } catch { /* fall through to goto */ }
      if (!clicked) {
        try { await page.goto(new URL(m.href!, input.baseUrl).href, { waitUntil: "domcontentloaded", timeout: 12000 }); } catch { /* timeout ok */ }
      }
      await page.waitForTimeout(800);
      const apis = await since(before);
      interactions.push({ route: m.href!, kind: "menu", label: m.text!, apis: [...new Set(apis)] });
      routesVisited.push(m.href!);
      if (clicked) paramSamples.push(...await paramMatrix(page, m.href!, "menu"));
    }

    // ---- tabs ----
    await page.goto(input.baseUrl, { waitUntil: "domcontentloaded", timeout: 30000 }).catch(() => {});
    await page.waitForTimeout(1200);
    const tabs = await page.locator("[role=tab], .ant-tabs-tab, .el-tabs__item, [class*=tab]").all();
    let tabClicks = 0;
    for (const t of tabs) {
      if (tabClicks >= cap) break;
      const label = ((await t.textContent().catch(() => "")) ?? "").trim().slice(0, 30);
      if (!label || SAFE_LABEL_RE.test(label)) continue;
      const before = await mark();
      await t.click({ timeout: 4000 }).catch(() => {});
      await page.waitForTimeout(700);
      const apis = await since(before);
      if (apis.length > 0) interactions.push({ route: page.url().replace(input.baseUrl, ""), kind: "tab", label, apis: [...new Set(apis)] });
      tabClicks++;
    }

    // ---- table row actions (view/detail/edit on first row) ----
    const rowActions = await page.locator("table tbody tr:first-child a, table tbody tr:first-child button, [class*=table] [class*=row] button").all();
    let rowClicks = 0;
    for (const b of rowActions) {
      if (rowClicks >= 4) break;
      const label = ((await b.textContent().catch(() => "")) ?? "").trim().slice(0, 30);
      if (!label || SAFE_LABEL_RE.test(label)) continue;
      const before = await mark();
      await b.click({ timeout: 4000 }).catch(() => {});
      await page.waitForTimeout(700);
      const apis = await since(before);
      if (apis.length > 0) interactions.push({ route: page.url().replace(input.baseUrl, ""), kind: "table-action", label, apis: [...new Set(apis)] });
      rowClicks++;
    }

    // ---- toolbar (export/filter/create — skip destructive) ----
    const toolbarBtns = await page.locator("button, [role=button]").all();
    let toolClicks = 0;
    for (const b of toolbarBtns) {
      if (toolClicks >= 6) break;
      const label = ((await b.textContent().catch(() => "")) ?? "").trim().slice(0, 30);
      if (!label || SAFE_LABEL_RE.test(label)) continue;
      // only action-y buttons on tables/forms
      if (!/search|query|filter|export|create|new|add|refresh|reload|查看|搜索|筛选|导出|新建|添加|刷新/i.test(label)) continue;
      const before = await mark();
      await b.click({ timeout: 4000 }).catch(() => {});
      await page.waitForTimeout(700);
      const apis = since ? await since(before) : [];
      const apis2 = apis || [];
      interactions.push({ route: page.url().replace(input.baseUrl, ""), kind: "toolbar", label, apis: [...new Set(apis2)] });
      toolClicks++;
    }

    const apiLog = await readLog();
    void paramSamples;
    const body = JSON.stringify({ baseUrl: input.baseUrl, routesVisited, interactions, apiLog, paramSamples }, null, 2);
    const path = join(input.outputRoot, "coverage.json");
    await writeFile(path, body);
    return { baseUrl: input.baseUrl, routesVisited, interactions, apiLog, paramSamples, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
  } finally {
    await browser.close();
  }
};

/** Per-module parameter trigger matrix (api-recon 3b): list-first-screen,
 *  search, advanced filter, create — one recorded sample each. */
const paramMatrix = async (page: import("playwright-core").Page, route: string, kind: string): Promise<CoverageResult["paramSamples"]> => {
  const out: CoverageResult["paramSamples"] = [];
  const detail = async (): Promise<{ method: string; url: string; reqBody: string | null }[]> =>
    ((await page.evaluate(`(window.__API_RECON_DETAIL__ || [])
      .filter(function(e){ return !/[.](?:js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map)(?:[?#]|$)/i.test(String(e.url)) })`)) as { method: string; url: string; reqBody: string | null }[]);
  const base = await detail();
  for (const e of base.slice(-30)) {
    let u: URL;
    try { u = new URL(e.url, "http://x.invalid"); } catch { continue; }
    out.push({
      path: u.pathname,
      method: e.method,
      action: `${kind}-first-screen`,
      query: u.search,
      body: (e.reqBody ?? "").slice(0, 400),
    });
  }
  // search box trigger: type a keyword and press enter, then diff
  try {
    const searchBox = page.locator("input[type=search], input[placeholder*=搜索 i], input[placeholder*=search i]").first();
    if ((await searchBox.count()) > 0) {
      const before = await detail();
      await searchBox.fill("velric").catch(() => {});
      await page.keyboard.press("Enter");
      await page.waitForTimeout(800);
      const after = await detail();
      const bset = new Set(before.map((x) => x.url));
      for (const e of after.filter((x) => !bset.has(x.url)).slice(-10)) {
        let u: URL;
        try { u = new URL(e.url, "http://x.invalid"); } catch { continue; }
        out.push({ path: u.pathname, method: e.method, action: "search", query: u.search, body: (e.reqBody ?? "").slice(0, 400) });
      }
    }
  } catch { /* no search box */ }
  return out;
};
