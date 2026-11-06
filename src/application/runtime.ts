import { join } from "node:path";
import { chromium, type Page, type Request } from "playwright-core";
import { hashRequest, hashResponse, recordReceipt, executionRunId } from "../core/execution.js";
import { principalHash, sameOrigin } from "../core/credentials.js";
import { mergeBrowserSamples, writeOwnedManifest } from "./harvest.js";

import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import {
  DEFAULT_HOOK_CONFIG,
  buildPreloadScript,
  type HookConfig,
} from "../domain/preload.js";

export interface BrowserRequestObservation {
  requestId: number; method: string; url: string; documentUrl: string;
  resourceType: string; reqBody: string | null; reqHeaders: Record<string, string>;
  status: number; complete: boolean; error?: string; responseHash?: string | null;
  receiptId?: string; source: string;
}
/** Node-side request identity survives every document and does not trust hooks. */
export const observeBrowserRequests = (page: Page) => {
  let sequence = 0;
  const requests: BrowserRequestObservation[] = [];
  const entries = new Map<Request, BrowserRequestObservation>();
  const pending = new Set<Promise<void>>();
  let failure: unknown;
  const start = (request: Request): void => {
    let documentUrl = request.url();
    try { if (!request.isNavigationRequest()) documentUrl = request.frame().url(); } catch {}
    const row: BrowserRequestObservation = { requestId: ++sequence, method: request.method(), url: request.url(), documentUrl,
      resourceType: request.resourceType(), reqBody: request.postData(), reqHeaders: request.headers(), status: 0, complete: false, source: "browser-network" };
    entries.set(request, row); requests.push(row);
  };
  const finish = (request: Request, failed: boolean): void => {
    const row = entries.get(request);
    if (!row) return;
    const work = (async () => {
      row.reqHeaders = await request.allHeaders().catch(() => row.reqHeaders);
      const response = await request.response();
      row.status = response?.status() ?? 0;
      row.complete = !failed && !!response && !(await response.finished());
      if (failed) row.error = request.failure()?.errorText ?? "browser request failed";
      if (response && row.complete && ["fetch", "xhr"].includes(row.resourceType)) {
        const length = Number(response.headers()["content-length"]);
        if (Number.isFinite(length) && length >= 0 && length <= 4 * 1024 * 1024) {
          row.responseHash = await response.body().then(hashResponse).catch(() => null);
        }
      }
      // A request event can describe an abort before any transport occurred.
      // Only a browser response proves the network boundary was reached.
      if (response && executionRunId() !== "unbound") {
        const receipt = await recordReceipt({ url: row.url, method: row.method, status: row.status || null,
          requestHash: hashRequest(request.postDataBuffer() ?? undefined, row.reqHeaders), responseHash: row.responseHash ?? null,
          principal: principalHash(row.reqHeaders), complete: row.complete, finalUrl: response?.url() ?? null });
        row.receiptId = receipt.id;
      }
    })();
    pending.add(work); work.then(() => pending.delete(work), err => { failure = err; pending.delete(work); });
  };
  const success = (r: Request): void => finish(r, false);
  const failed = (r: Request): void => finish(r, true);
  page.on("request", start); page.on("requestfinished", success); page.on("requestfailed", failed);
  return { requests, drain: async () => {
    // Bounded drain: SSE/long-poll responses may never finish, and a single
    // failed collector must not discard the whole capture. Wait up to 10s,
    // then surface failures as console warnings instead of throwing.
    const timeout = new Promise<void>((done) => setTimeout(done, 10_000));
    await Promise.race([Promise.all([...pending]), timeout]);
    if (failure) console.warn(`[runtime] network collector failure: ${failure instanceof Error ? failure.message : String(failure)}`);
  }, close: () => {
    page.off("request", start); page.off("requestfinished", success); page.off("requestfailed", failed);
  } };
};

export interface RuntimeCaptureInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly routes?: string[];
  readonly cookies?: { name: string; value: string; path?: string }[];
  readonly localStorage?: Record<string, string>;
  readonly hook?: Partial<HookConfig>;
  readonly stubs?: { match: string; body: unknown }[];
  readonly chromiumPath?: string;
  readonly headless?: boolean;
  readonly proxy?: string;
  readonly waitMs?: number;
  readonly perRouteMs?: number;
  readonly routeTimeoutMs?: number;
  readonly recordWs?: boolean;
  readonly captureResponses?: boolean;
  readonly maxRoutes?: number;
  readonly mode?: "passive" | "gate-defeat";
}

export interface RuntimeCaptureResult {
  readonly shell: {
    readonly url: string;
    readonly loginForm: boolean;
    readonly links: string[];
  };
  readonly routesVisited: string[];
  readonly uniqueCalls: string[];
  readonly perRoute: Record<string, string[]>;
  readonly details: number;
  readonly wsEndpoints: string[];
  readonly wsFrames: number;
  readonly sseEndpoints: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

/** Runtime-capture noise filter: drop static-asset and telemetry hosts from
 * the API surface (SVG icon JSON, GA/sentry beacons pollute uniqueCalls). */
const NOISE_HOST_RE =
  /(?:^|\.)(?:google-analytics\.com|googletagmanager\.com|doubleclick\.net|sentry\.io|.*\.sentry\.io|beacon\.qq\.com|hm\.baidu\.com|plural\.sc\.qq\.com|beacon\.shimo\.io|stats\.g\.doubleclick\.net|browser\.events\.data\.microsoft\.com|.*\.clarity\.ms|.*\.onelinks\.pro|marketing_track\..*|.*-track\..*)$/i;

const STATIC_RESOURCE_RE =
  /\.(?:js|css|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|eot|mp4|webm|mp3|m4a|wav|flv|ts|m3u8|vtt|json\.sig|map|har)(?:[?#@]|$)/i;

/** Icon/font packages fetched as JSON from asset CDNs (e.g. …/svg-next/arrow/v3.json). */
const ICON_PACKAGE_PATH_RE = /\/svg[-_]|\/icons?[-_/]|\/fonts?[-_/]/i;

const isNoiseUrl = (rawUrl: string, pageOrigin?: string): boolean => {
  try {
    const u = new URL(rawUrl, "http://placeholder.local");
    if (NOISE_HOST_RE.test(u.hostname)) return true;
    if (STATIC_RESOURCE_RE.test(u.pathname)) return true;
    // Static asset paths on CDN hosts (/_next/static/, /assets/, /dist/) —
    // resource delivery, not API surface, regardless of extension.
    if (/(?:^|\/)_(?:next|astro|remix|nuxt)\/|\/static\/js\/|\/(?:dist|build)\/assets\//.test(u.pathname)) return true;
    // Cross-origin svg/icon delivery paths are static packages, not APIs.
    if (pageOrigin && u.origin !== pageOrigin && ICON_PACKAGE_PATH_RE.test(u.pathname)) return true;
    return false;
  } catch {
    return false;
  }
};

const cookieValue = (v: string): string => {
  if (v.startsWith("b64json:")) return Buffer.from(v.slice(8)).toString("base64");
  if (v.startsWith("json:")) return v.slice(5);
  return v;
};

const chromiumSandboxArgs = (): string[] => {
  // --no-sandbox only when actually running as root (container convention);
  // an unprivileged user keeps the renderer sandbox for hostile-bundle safety.
  const base = ["--disable-dev-shm-usage", "--ignore-certificate-errors"];
  return process.getuid?.() === 0 ? ["--no-sandbox", ...base] : base;
};

/** Find a usable Chromium executable: explicit path, then common Linux names. */
const findChromium = async (): Promise<string> => {
  const { access } = await import("node:fs/promises");
  const candidates = [
    process.env.VELRIC_CHROMIUM,
    process.env.CHROMIUM,
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
  ].filter((c): c is string => typeof c === "string" && c.length > 0);
  for (const c of candidates) {
    try {
      await access(c);
      return c;
    } catch {
      /* next */
    }
  }
  throw {
    code: "chromium_not_found",
    message: "no Chromium executable found",
    remediation:
      "install Chromium or pass chromiumPath / VELRIC_CHROMIUM / CHROMIUM",
  };
};

/**
 * Headless runtime capture (port of runtime_harvest.js on playwright-core):
 * inject the preload hook at document start, walk every route, record the live
 * XHR/fetch/WS surface with methods, bodies, and response samples.
 */
export const captureRuntime = async (
  input: RuntimeCaptureInput,
): Promise<RuntimeCaptureResult> => {
  const base = input.baseUrl.startsWith("http")
    ? input.baseUrl
    : `https://${input.baseUrl}`;
  const origin = new URL(base).origin;
  const root = await ensureDir(input.outputRoot);
  const execPath = input.chromiumPath ?? (await findChromium());
  const hook: HookConfig = {
    ...DEFAULT_HOOK_CONFIG,
    ...input.hook,
    stubs: input.stubs ?? input.hook?.stubs ?? [],
    mode: input.mode ?? input.hook?.mode ?? "passive",
  };

  // Proxy credentials go through launch({proxy}) (never argv): a userinfo
  // URL on the chromium command line leaks into /proc for local users.
  const proxyOpts = input.proxy ? (() => { try { const u = new URL(input.proxy!); return { server: `${u.protocol}//${u.hostname}:${u.port}`, ...(u.username ? { username: decodeURIComponent(u.username) } : {}), ...(u.password ? { password: decodeURIComponent(u.password) } : {}) }; } catch { return { server: input.proxy! }; } })() : undefined;
  const browser = await chromium.launch({
    executablePath: execPath,
    headless: input.headless ?? true,
    proxy: proxyOpts,
    // No-credential proxies may also go via argv; credentialed ones must not.
    args: [...chromiumSandboxArgs(), ...((input.proxy && !proxyOpts) ? [`--proxy-server=${input.proxy}`] : [])],
  });

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    await context.route("**/*", route => sameOrigin(route.request().url(), base) ? route.continue() : route.abort("blockedbyclient"));
    const page = await context.newPage();
    const network = observeBrowserRequests(page);

    // document-start hook injection
    await page.addInitScript(buildPreloadScript(hook));
    if (input.localStorage) {
      await page.addInitScript(
        `(() => { try { if(location.origin !== ${JSON.stringify(origin)}) return; const kv = ${JSON.stringify(input.localStorage)}; for (const k in kv) localStorage.setItem(k, kv[k]); } catch {} })()`,
      );
    }

    // WebSocket frames via CDP
    const wsFrames: { url: string; dir: string; data: string }[] = [];
    if (input.recordWs ?? true) {
      const cdp = await context.newCDPSession(page);
      await cdp.send("Network.enable");
      const wsUrl: Record<string, string> = {};
      cdp.on("Network.webSocketCreated", (e) => {
        wsUrl[String(e.requestId)] = String(e.url);
      });
      const onFrame = (dir: string) => (e: Record<string, unknown>) => {
        const resp = e.response as { payloadData?: string } | undefined;
        const payload = resp?.payloadData;
        if (payload != null) {
          const url = wsUrl[String(e.requestId)] ?? "";
          wsFrames.push({ url: url.replace(origin, ""), dir, data: payload.slice(0, hook.respMax) });
        }
      };
      cdp.on("Network.webSocketFrameSent", onFrame("send"));
      cdp.on("Network.webSocketFrameReceived", onFrame("recv"));
    }

    if (input.cookies) {
      await context.addCookies(
        input.cookies.map((c) => ({
          name: c.name,
          value: cookieValue(c.value),
          url: origin + (c.path ?? "/"),
        })),
      );
    }

    await page.goto(base, {
      waitUntil: "domcontentloaded",
      timeout: 45000,
    });
    await page.waitForTimeout(input.waitMs ?? 1200);

    const shell = await page.evaluate(`(() => ({
      url: location.href,
      loginForm: !!document.querySelector("input[type=password]"),
      links: [...document.querySelectorAll('a[href^="/"]')].map((a) =>
        a.getAttribute("href"),
      ),
    }))()`) as {
      url: string;
      loginForm: boolean;
      links: (string | null)[];
    };
    const shellLinks = shell.links.filter((h): h is string => !!h && h.length > 1);
    // Route fan-out cap: runtime's job is API-surface enumeration, not full-site
    // mirroring. Heavy SPAs expose hundreds of live-DOM links (~100+);
    // visiting them all starves the route loop on modest hardware. Explicit
    // input.routes take priority; discovered shell links are capped.
    const maxRoutes = input.maxRoutes ?? 30;
    const explicit = input.routes ?? [];
    let fallbackRoutes: string[] = [];
    if (explicit.length === 0 && shellLinks.length === 0) {
      // Neither explicit routes nor discovered shell links: fall back to the
      // static harvest's path list so the route loop still has fuel.
      try {
        const { readFile } = await import("node:fs/promises");
        const paths = (await readFile(join(root, "paths_other.txt"), "utf8"))
          .split("\n").map((l) => l.trim()).filter((l) => l.startsWith("/"));
        fallbackRoutes = paths.slice(0, maxRoutes);
      } catch {
        fallbackRoutes = ["/"];
      }
    }
    const seedRoutes = [...new Set([...(input.routes ?? ["/"]), ...shellLinks, ...fallbackRoutes])];
    const routes = seedRoutes.flatMap(raw => {
      try { const u = new URL(raw, origin); return sameOrigin(u.href, base) ? [u.pathname + u.search + u.hash] : []; } catch { return []; }
    }).slice(0, maxRoutes);
    const perRoute: Record<string, string[]> = {};
    const allApis = new Set<string>();
    const allDetail: {
      method: string; url: string; status: number;
      reqBody: string | null; responseBody: string | null; source: string; documentId?: string; requestId?: number;
    }[] = [];
    const allVueRoutes = new Set<string>();
    const observeAcc: { storage: unknown[]; headers: { name: string; url: string }[] } = {
      storage: [],
      headers: [],
    };
    const collected = new Set<string>();
    // Read the live document's hook state and fold it into the totals. The hook
    // state resets on every navigation, so each document must be collected
    // while it is still the active page.
    const collect = async (key: string): Promise<void> => {
      const fresh = await page.evaluate(`(() => {
        const w = window;
        const obs = w.__API_RECON_OBSERVE__ || { storage: [], headers: [] };
        return {
          apis: [...(w.__API_RECON_LOG__ || [])],
          detail: (w.__API_RECON_DETAIL__ || []).slice(-2000),
          routes: [...(w.__API_RECON_ROUTES__ || [])],
          observe: { storage: obs.storage.slice(-200), headers: obs.headers.slice(-500) },
        };
      })()`) as {
        apis: string[];
        detail: { method: string; url: string; status: number; reqBody: string | null; responseBody: string | null; source: string; documentId?: string; requestId?: number }[];
        routes: string[];
        observe: { storage: unknown[]; headers: { name: string; url: string }[] };
      };
      const keptApis = fresh.apis.filter((a) => !isNoiseUrl(a.split(" ").slice(1).join(" ") || a, origin));
      perRoute[key] = [...new Set([...(perRoute[key] ?? []), ...keptApis])];
      for (const a of keptApis) allApis.add(a);
      for (const detail of fresh.detail.filter(d => !isNoiseUrl(String(d.url), origin))) {
        const id = `${detail.documentId}:${detail.requestId}`;
        if (!collected.has(id)) { collected.add(id); allDetail.push(detail); }
      }
      for (const r of fresh.routes) allVueRoutes.add(r);
      observeAcc.storage.push(...fresh.observe.storage);
      observeAcc.headers.push(...fresh.observe.headers);
    };
    // Boot phase: the entry document is live right now; collect it before the
    // route loop navigates away (its initial API burst is otherwise lost).
    await collect(new URL(shell.url).pathname);
    for (const rt of routes) {
      try {
        await page.goto(origin + rt, {
          waitUntil: "domcontentloaded",
          timeout: input.routeTimeoutMs ?? 12000,
        });
      } catch {
        /* route timeout is data, not failure */
      }
      await page.waitForTimeout(input.perRouteMs ?? 900);
      await collect(rt);
    }

    await network.drain(); network.close();
    for (const row of network.requests.filter(r => ["fetch", "xhr"].includes(r.resourceType) && !isNoiseUrl(r.url, origin))) allApis.add(`${row.method} ${row.url}`);
    const uniqueCalls = [...allApis].sort();
    const wsUniq = [...new Set(wsFrames.map((f) => f.url))].filter(Boolean).sort();

    const artifacts: { path: string; bytes: number }[] = [];
    artifacts.push(
      await writeArtifact(
        root,
        "runtime_api.json",
        JSON.stringify(
          {
            shell,
            mode: hook.mode,
            requests: network.requests,
            limitations: ["same-origin capture; external requests blocked", ...(hook.mode === 'gate-defeat' ? ["hook responses may be modified; only transport receipts describe network observations"] : [])],
            uniqueCalls,
            perRoute,
            detail: allDetail.slice(-4000),
            routes: [...allVueRoutes].sort(),
            observe: {
              storage: observeAcc.storage.slice(-1000),
              headers: observeAcc.headers.slice(-2000),
            },
            wsEndpoints: wsUniq,
            wsFrames,
          },
          null,
          2,
        ),
      ),
    );
    // api_merged is the canonical endpoint list for downstream stages
    // (auth_probe / batch summary / run_diff). Write it even when no static
    // corpus exists — runtime-only endpoints (spec/API descriptor docs) must not
    // be silently dropped.
    {
      let staticList = "";
      try {
        const { readFile } = await import("node:fs/promises");
        staticList = await readFile(`${root}/api_static.txt`, "utf8");
      } catch {
        /* api_static.txt absent — runtime-only run */
      }
      const merged = new Set<string>([
        ...uniqueCalls.map((c) => c.split(" ").slice(1).join(" ")),
        ...staticList.split("\n").filter(Boolean),
      ]);
      artifacts.push(
        await writeArtifact(root, "api_merged.txt", [...merged].sort().join("\n")),
      );
    }
    // param_samples.json: bridge runtime detail → merge_params input, so the
    // recorded traffic feeds the parameter-matrix step without manual reshaping.
    {
      const paramSamples = network.requests
        .filter(d => ["fetch", "xhr"].includes(d.resourceType) && (d.reqBody || d.url.includes("?")))
        .map((d) => ({
          method: d.method,
          url: String(d.url).startsWith("http")
            ? String(d.url)
            : new URL(String(d.url), origin).href,
          body: d.reqBody,
          query: String(d.url).includes("?") ? String(d.url).split("?")[1] ?? null : null,
        }));
      artifacts.push(await mergeBrowserSamples(root, base, "runtime", paramSamples));
    }
    artifacts.push(await writeOwnedManifest(root, "runtime_manifest.json", "runtime", base, artifacts, network.requests.filter(r => ["fetch", "xhr"].includes(r.resourceType)).length));

    return {
      shell: { url: shell.url, loginForm: shell.loginForm, links: shellLinks },
      routesVisited: routes,
      uniqueCalls,
      perRoute,
      details: allDetail.length,
      wsEndpoints: wsUniq,
      wsFrames: wsFrames.length,
      sseEndpoints: [...new Set([...allApis].filter((a) => a.startsWith("SSE ")).map((a) => a.slice(4)))],
      artifacts,
    };
  } finally {
    await browser.close();
  }
};