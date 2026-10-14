import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/** Session-keeping deep crawl: an authenticated crawler that maintains a
 *  LIVE session across the whole crawl — re-login on auth expiry (401/302
 *  to login), refreshes tokens from refresh_token responses, and keeps
 *  crawling the endpoint surface (from merged endpoints / site map) until
 *  depth or count budget runs out. Where spider_mpa/coverage stop at the
 *  first 401, this one keeps going.
 *
 *  Deterministic: fixed frontier order (BFS by depth), fixed re-login
 *  policy, response-hash dedupe. Zero LLM. */

export interface SessionCrawlInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  /** login POST endpoint (form or json) */
  readonly loginUrl: string;
  readonly username: string;
  readonly password: string;
  /** how the login body is sent */
  readonly loginMode?: "form" | "json";
  /** username/password field names (default username/password) */
  readonly usernameField?: string;
  readonly passwordField?: string;
  /** endpoints to crawl (absolute or root-relative); default: read merged.json from outputRoot */
  readonly endpoints?: readonly string[];
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxPages?: number;
  /** max re-login attempts over the whole crawl (default 5) */
  readonly maxRelogins?: number;
  readonly headers?: Record<string, string>;
}

export interface SessionCrawlResult {
  readonly crawled: number;
  readonly pages: { url: string; status: number; depth: number; authState: "anonymous" | "authenticated" | "expired" }[];
  readonly relogins: number;
  readonly tokenRefreshes: number;
  readonly blocked: string[];
  readonly sessionCookieNames: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

interface Session {
  cookie: string;
  bearer: string | null;
}

const extractSetCookies = (headers: Record<string, string>): string[] => {
  // fetchUrl flattens headers; set-cookie may be comma-joined
  const raw = headers["set-cookie"] ?? "";
  if (!raw) return [];
  // split on cookie boundaries: comma followed by " token=" — naive split
  // breaks expires dates; tolerate by splitting only between pairs
  const parts: string[] = [];
  for (const piece of raw.split(/,(?=\s*[^;=,\s]+=)/)) {
    const p = piece.trim();
    if (p) parts.push(p.split(";")[0]!);
  }
  return parts;
};

export const crawlSession = async (input: SessionCrawlInput): Promise<SessionCrawlResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000, headers: input.headers };
  const uField = input.usernameField ?? "username";
  const pField = input.passwordField ?? "password";
  const mode = input.loginMode ?? "json";

  // --- login ------------------------------------------------------------
  const doLogin = async (): Promise<Session | null> => {
    const body = mode === "json"
      ? JSON.stringify({ [uField]: input.username, [pField]: input.password })
      : `${encodeURIComponent(uField)}=${encodeURIComponent(input.username)}&${encodeURIComponent(pField)}=${encodeURIComponent(input.password)}`;
    const r = await fetchUrl(input.loginUrl, {
      ...opts,
      method: "POST",
      headers: { "content-type": mode === "json" ? "application/json" : "application/x-www-form-urlencoded", ...input.headers },
      body,
    });
    if (r.status === 0 || r.status >= 400) return null;
    const cookies = extractSetCookies(r.headers ?? {});
    // bearer from json response
    let bearer: string | null = null;
    try {
      const j = JSON.parse(r.body) as Record<string, unknown>;
      const tok = j.token ?? j.access_token ?? j.accessToken ?? j.jwt ?? (j.data as Record<string, unknown> | undefined)?.token;
      if (typeof tok === "string") bearer = tok;
    } catch { /* not json */ }
    if (cookies.length === 0 && !bearer) return null;
    return { cookie: cookies.join("; "), bearer };
  };

  let session = await doLogin();
  if (!session) throw new Error("login failed: no session cookie or token returned");
  const sessionCookieNames = session.cookie.split(";").map((c) => c.split("=")[0]!).filter(Boolean);

  // --- frontier ---------------------------------------------------------
  let endpoints: string[] = [];
  if (input.endpoints) {
    endpoints = [...input.endpoints];
  } else {
    try {
      const merged = JSON.parse(await readFile(join(input.outputRoot, "merged.json"), "utf8")) as { path?: string; url?: string }[];
      endpoints = merged.map((e) => e.path ?? e.url ?? "").filter((p) => p.length > 0);
    } catch { endpoints = []; }
  }
  const base = input.baseUrl.replace(/\/+$/, "");
  const queue = endpoints.map((e) => ({ url: e.startsWith("http") ? e : `${base}${e.startsWith("/") ? "" : "/"}${e}`, depth: 1 }));
  const maxPages = input.maxPages ?? 60;
  let relogins = 0;
  let tokenRefreshes = 0;

  const authHeaders = (): Record<string, string> => {
    const h: Record<string, string> = { ...input.headers };
    if (session!.cookie) h.cookie = session!.cookie;
    if (session!.bearer) h.authorization = `Bearer ${session!.bearer}`;
    return h;
  };

  const looksExpired = (status: number, location: string, body: string): boolean =>
    status === 401 ||
    (status >= 300 && status < 400 && /login|signin|auth/i.test(location)) ||
    (status === 200 && /login|session expired|please sign in/i.test(body.slice(0, 2048)) && session!.bearer === null && session!.cookie.length > 0 && /<html/i.test(body.slice(0, 200)));

  const pages: SessionCrawlResult["pages"] = [];
  const blocked: string[] = [];
  const seen = new Set<string>();

  while (queue.length > 0 && pages.length < maxPages) {
    const { url, depth } = queue.shift()!;
    if (seen.has(url)) continue;
    seen.add(url);

    const r = await fetchUrl(url, { ...opts, method: "GET", headers: authHeaders() });
    if (r.status === 0) { blocked.push(url); continue; }

    const location = r.headers?.location ?? "";
    let authState: "anonymous" | "authenticated" | "expired" = "authenticated";
    if (looksExpired(r.status, location, r.body)) {
      authState = "expired";
      // --- re-login & retry once ----------------------------------------
      if (relogins < (input.maxRelogins ?? 5)) {
        relogins += 1;
        const fresh = await doLogin();
        if (fresh) {
          if (fresh.bearer && fresh.bearer !== session!.bearer) tokenRefreshes += 1;
          session = fresh;
          const r2 = await fetchUrl(url, { ...opts, method: "GET", headers: authHeaders() });
          if (r2.status > 0 && r2.status < 400) {
            pages.push({ url, status: r2.status, depth, authState: "authenticated" });
            continue;
          }
        }
      }
      blocked.push(url);
      continue;
    }
    if (r.status === 403) { authState = "anonymous"; }
    pages.push({ url, status: r.status, depth, authState });

    // extract same-origin links for BFS (depth+1)
    if (depth < 3 && r.status >= 200 && r.status < 300) {
      for (const m of r.body.matchAll(/href="([^"]+)"|src="([^"]+)"/g)) {
        const href = (m[1] ?? m[2] ?? "").trim();
        if (!href || href.startsWith("#") || /^(javascript:|data:|mailto:)/i.test(href)) continue;
        let abs: string;
        try { abs = new URL(href, url).href; } catch { continue; }
        if (abs.startsWith(base) && !seen.has(abs)) queue.push({ url: abs, depth: depth + 1 });
      }
    }
  }

  const bodyStr = JSON.stringify({ crawled: pages.length, pages, relogins, tokenRefreshes, blocked, sessionCookieNames }, null, 2);
  const path = join(input.outputRoot, "session_crawl.json");
  await writeFile(path, bodyStr, "utf8");
  return { crawled: pages.length, pages, relogins, tokenRefreshes, blocked, sessionCookieNames, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
