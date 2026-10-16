import { fetchUrl, type FetchResult } from "../adapters/http.js";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { SessionJar, normalizeHeaders, sameOrigin } from "../core/credentials.js";
import { executionRunId } from "../core/execution.js";

export interface SessionCrawlInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly loginUrl: string;
  readonly username: string;
  readonly password: string;
  readonly loginMode?: "form" | "json";
  readonly usernameField?: string;
  readonly passwordField?: string;
  readonly endpoints?: readonly string[];
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxPages?: number;
  readonly maxRelogins?: number;
  readonly headers?: Record<string, string>;
  readonly loggedInRegex?: string;
  readonly loggedOutRegex?: string;
  /** Known authenticated resource. A positive marker here verifies identity. */
  readonly authCheckUrl?: string;
}
export interface SessionCrawlResult {
  readonly crawled: number;
  readonly pages: { url: string; status: number; depth: number; authState: "anonymous" | "authenticated" | "expired" | "unknown" }[];
  readonly relogins: number;
  readonly tokenRefreshes: number;
  readonly blocked: string[];
  readonly sessionCookieNames: string[];
  readonly authentication: "verified" | "inconclusive";
  readonly artifacts: { path: string; bytes: number }[];
}

const setCookies = (r: FetchResult): readonly string[] => r.setCookies?.length ? r.setCookies : (r.headers["set-cookie"] ?? "").split(/,(?=\s*[^;=,\s]+=)/).filter(Boolean);
const tokenFrom = (r: FetchResult): string | null => {
  const header = r.headers.authorization?.replace(/^Bearer\s+/i, "") ?? r.headers["x-access-token"];
  if (header) return header;
  try {
    const j = JSON.parse(r.body);
    for (const node of [j, j?.data]) for (const name of ["access_token", "accessToken", "token", "jwt"]) {
      if (typeof node?.[name] === "string" && node[name]) return node[name];
    }
  } catch { /* non-JSON responses can still rotate cookies */ }
  return null;
};

export const crawlSession = async (input: SessionCrawlInput): Promise<SessionCrawlResult> => {
  await ensureDir(input.outputRoot);
  const base = new URL(input.baseUrl), loginUrl = new URL(input.loginUrl, base).href;
  if (!/^https?:$/.test(base.protocol) || !sameOrigin(loginUrl, base.href)) throw new Error("login must be same-origin HTTP(S)");
  const jar = new SessionJar(), headers = normalizeHeaders(input.headers);
  if (headers.cookie) jar.update(base.href, headers.cookie.split(";").map(pair => `${pair.trim()}; Path=/`));
  if (headers.authorization?.startsWith("Bearer ")) jar.setBearer(base.origin, headers.authorization.slice(7));
  delete headers.cookie; delete headers.authorization;
  let relogins = 0, tokenRefreshes = 0, bearer = "", verified = false;
  const loggedIn = input.loggedInRegex ? new RegExp(input.loggedInRegex) : null;
  const loggedOut = input.loggedOutRegex ? new RegExp(input.loggedOutRegex) : null;
  const blocked = new Set<string>();
  const state = (r: FetchResult): "authenticated" | "expired" | "unknown" => {
    if (r.status === 0 || r.complete === false || r.status >= 500 || r.status === 429) return "unknown";
    if (r.status === 401 || loggedOut?.test(r.body) || /<input\b[^>]*type\s*=\s*["']?password\b/i.test(r.body) || /session expired|please sign in/i.test(r.body)) return "expired";
    if (r.status >= 300 && r.status < 400 && /login|signin|auth/i.test(r.headers.location ?? "")) return "expired";
    if (r.status >= 200 && r.status < 300 && loggedIn?.test(r.body)) return "authenticated";
    return "unknown";
  };
  const update = (url: string, r: FetchResult): void => {
    jar.update(url, setCookies(r));
    if (r.complete === false || r.status < 200 || r.status >= 300) return;
    const token = tokenFrom(r);
    if (token && token !== bearer) { if (bearer) tokenRefreshes++; bearer = token; jar.setBearer(base.origin, token); }
  };
  // Redirects stay inside the declared origin, update the jar at every hop,
  // and never forward a POST credential body to an unrelated destination.
  const request = async (url: string, method = "GET", body?: string): Promise<FetchResult> => {
    let current = url;
    for (let hop = 0; ; hop++) {
      if (!sameOrigin(current, base.href)) throw new Error("cross-origin session request refused");
      const r = await fetchUrl(current, { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000, redirect: "manual", method, body,
        headers: { ...headers, ...jar.headers(current), ...(body === undefined ? {} : { "content-type": input.loginMode === "form" ? "application/x-www-form-urlencoded" : "application/json" }) } });
      update(current, r);
      if (![301, 302, 303, 307, 308].includes(r.status) || !r.headers.location || hop >= 5 || state(r) === "expired") return r;
      const next = new URL(r.headers.location, current).href;
      if (!sameOrigin(next, base.href)) { blocked.add(next); return r; }
      if (r.status === 303 || ((r.status === 301 || r.status === 302) && method === "POST")) { method = "GET"; body = undefined; }
      current = next;
    }
  };
  const doLogin = async (): Promise<boolean> => {
    verified = false;
    const before = JSON.stringify(jar.headers(base.href));
    const fields = { [input.usernameField ?? "username"]: input.username, [input.passwordField ?? "password"]: input.password };
    const r = await request(loginUrl, "POST", input.loginMode === "form" ? new URLSearchParams(fields).toString() : JSON.stringify(fields));
    if (r.status < 200 || r.status >= 400 || r.complete === false || state(r) === "expired") return false;
    const credentials = jar.headers(base.href);
    const changed = before !== JSON.stringify(credentials);
    // Credential changes are candidates, not proof of authenticated access.
    // CSRF/locale/guest cookies alone must not qualify even as candidates.
    const candidate = changed && (!!credentials.authorization || /(?:^|;\s*)(?:[^=;]*(?:sess|auth|token|jwt|login)[^=;]*|sid)=/i.test(credentials.cookie ?? ""));
    if (state(r) === "authenticated") verified = true;
    if (input.authCheckUrl) {
      const check = new URL(input.authCheckUrl, base).href;
      if (!sameOrigin(check, base.href)) throw new Error("authCheckUrl must be same-origin");
      const proof = await request(check);
      if (state(proof) === "expired" || proof.status < 200 || proof.status >= 300) return false;
      verified = state(proof) === "authenticated";
    }
    return verified || candidate;
  };
  if (!await doLogin()) throw new Error("login failed: no authenticated marker or changed session credential");

  let endpoints = [...(input.endpoints ?? [])];
  if (!input.endpoints) {
    try { const entries = JSON.parse(await readFile(join(input.outputRoot, "merged.json"), "utf8")) as { path?: string; url?: string }[]; endpoints = entries.map(e => e.url ?? e.path ?? "").filter(Boolean); }
    catch (err) { if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err; }
  }
  const queue: { url: string; depth: number }[] = [];
  const enqueue = (raw: string, depth: number, from = base.href): void => {
    try { const u = new URL(raw, from); u.hash = ""; if (sameOrigin(u.href, base.href)) queue.push({ url: u.href, depth }); else blocked.add(u.href); } catch { blocked.add(raw); }
  };
  endpoints.forEach(url => enqueue(url, 1));
  const seen = new Set<string>(), pages: SessionCrawlResult["pages"] = [];
  while (queue.length && seen.size < (input.maxPages ?? 60)) {
    const { url, depth } = queue.shift()!;
    if (seen.has(url)) continue;
    seen.add(url);
    let r = await request(url), authState = state(r);
    if (authState === "expired") {
      verified = false;
      if (relogins < (input.maxRelogins ?? 5)) {
        relogins++;
        if (await doLogin()) { r = await request(url); authState = state(r); }
      }
      if (authState === "expired") { blocked.add(url); continue; }
    }
    if (r.status === 0 || r.complete === false) { blocked.add(url); continue; }
    if (authState === "authenticated") verified = true;
    pages.push({ url, status: r.status, depth, authState: r.status === 403 ? "anonymous" : authState });
    if (depth < 3 && r.status >= 200 && r.status < 300) for (const m of r.body.matchAll(/(?:href|src)=["']([^"']+)["']/g)) {
      const href = m[1]!;
      if (!/^(?:#|javascript:|data:|mailto:|tel:)/i.test(href)) enqueue(href, depth + 1, r.finalUrl ?? url);
    }
  }
  const sessionCookieNames = [...new Set(jar.header(base.href).split(/;\s*/).filter(Boolean).map(c => c.slice(0, c.indexOf("="))))];
  const result: SessionCrawlResult = { crawled: pages.length, pages, relogins, tokenRefreshes, blocked: [...blocked], sessionCookieNames, authentication: verified ? "verified" : "inconclusive", artifacts: [] };
  result.artifacts.push(await writeArtifact(input.outputRoot, "session_crawl.json", JSON.stringify(result, null, 2)));
  result.artifacts.push(await writeArtifact(input.outputRoot, "session_crawl_manifest.json", JSON.stringify({ producer: "session-crawl", target: base.href, runId: executionRunId(), count: pages.length, artifacts: result.artifacts, authentication: result.authentication }, null, 2)));
  return result;
};
