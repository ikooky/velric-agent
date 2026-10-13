import { chromium, type Browser, type BrowserContext, type Page } from "playwright-core";

import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import {
  DEFAULT_HOOK_CONFIG,
  buildPreloadScript,
  type HookConfig,
} from "../domain/preload.js";

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

const cookieValue = (v: string): string => {
  if (v.startsWith("b64json:")) return Buffer.from(v.slice(8)).toString("base64");
  if (v.startsWith("json:")) return v.slice(5);
  return v;
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
  };

  const browser = await chromium.launch({
    executablePath: execPath,
    headless: input.headless ?? true,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--ignore-certificate-errors",
      ...(input.proxy ? [`--proxy-server=${input.proxy}`] : []),
    ],
  });

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    // document-start hook injection
    await page.addInitScript(buildPreloadScript(hook));
    if (input.localStorage) {
      await page.addInitScript(
        `(() => { try { const kv = ${JSON.stringify(input.localStorage)}; for (const k in kv) localStorage.setItem(k, kv[k]); } catch {} })()`,
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
          domain: new URL(base).hostname,
          path: c.path ?? "/",
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
    const routes = [...new Set([...(input.routes ?? ["/"]), ...shellLinks])];
    const perRoute: Record<string, string[]> = {};
    const allApis = new Set<string>();
    const allDetail: {
      method: string; url: string; status: number;
      reqBody: string | null; responseBody: string | null; source: string;
    }[] = [];
    const allVueRoutes = new Set<string>();
    const observeAcc: { storage: unknown[]; headers: { name: string; url: string }[] } = {
      storage: [],
      headers: [],
    };
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
        detail: { method: string; url: string; status: number; reqBody: string | null; responseBody: string | null; source: string }[];
        routes: string[];
        observe: { storage: unknown[]; headers: { name: string; url: string }[] };
      };
      perRoute[key] = [...new Set([...(perRoute[key] ?? []), ...fresh.apis])];
      for (const a of fresh.apis) allApis.add(a);
      allDetail.push(...fresh.detail);
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
    // merge with static when present
    try {
      const { readFile } = await import("node:fs/promises");
      const staticList = await readFile(`${root}/api_static.txt`, "utf8");
      const merged = new Set<string>([
        ...uniqueCalls.map((c) => c.split(" ").slice(1).join(" ")),
        ...staticList.split("\n").filter(Boolean),
      ]);
      artifacts.push(
        await writeArtifact(root, "api_merged.txt", [...merged].sort().join("\n")),
      );
    } catch {
      /* api_static.txt absent — static merge skipped */
    }

    return {
      shell: { url: shell.url, loginForm: shell.loginForm, links: shellLinks },
      routesVisited: routes,
      uniqueCalls,
      perRoute,
      details: allDetail.length,
      wsEndpoints: wsUniq,
      wsFrames: wsFrames.length,
      sseEndpoints: [],
      artifacts,
    };
  } finally {
    await browser.close();
  }
};