import { createHash } from "node:crypto";
import { Agent, ProxyAgent, Socks5ProxyAgent, fetch as undiciFetch, request as undiciRequest, getGlobalDispatcher, type Dispatcher } from "undici";
import { acquire } from "../domain/rateLimit.js";
import { getProxyPool, setProxyPool, type ProxyPool } from "../domain/proxyPool.js";
import { executionRunId, executionSignal, recordReceipt } from "../core/execution.js";
import { principalHash, credentialScope, SessionJar } from "../core/credentials.js";

let globalRps = 0;
export const setGlobalRateLimit = (rps: number): void => { globalRps = Number.isFinite(rps) ? Math.max(0, rps) : 0; };
export const setGlobalProxyPool = setProxyPool;
export interface FetchOptions {
  /** Hard cap on transport attempts INCLUDING retries (default: 3 for
   *  idempotent, 1 otherwise). Callers with a wire-budget (differential
   *  probes) set 1 so a 503 does not silently triple their request count. */
  readonly maxAttempts?: number;
  readonly raw?: boolean;
  readonly redirect?: "follow" | "manual";
  readonly headers?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
  readonly queueTimeoutMs?: number;
  readonly signal?: AbortSignal;
  readonly proxy?: string;
  readonly proxyPool?: ProxyPool;
  /** Explicit target certificate policy, independent of proxy TLS. Default false for reconnaissance. */
  readonly rejectUnauthorized?: boolean;
  readonly proxyRejectUnauthorized?: boolean;
  readonly cookie?: string;
  readonly maxBytes?: number;
  readonly method?: string;
  readonly body?: string;
}
export interface FetchResult {
  readonly url: string; readonly finalUrl?: string | null;
  readonly status: number; readonly ok: boolean; readonly contentType: string;
  readonly headers: Record<string, string>; readonly setCookies?: readonly string[];
  readonly body: string; readonly bytes: number; readonly sha256: string;
  readonly complete?: boolean; readonly truncated?: boolean;
  readonly storedBytes?: number; readonly storedHash?: string; readonly receivedBytes?: number;
  readonly rawBuffer?: Buffer; readonly error?: string;
  readonly failureKind?: "invalid-request" | "cancelled" | "queue-timeout" | "transport-error" | "body-limit" | "proxy-exhausted";
  readonly receiptId?: string;
}
const hash = (v: string | Uint8Array): string => createHash("sha256").update(v).digest("hex");
const failure = (url: string, error: string, failureKind: FetchResult["failureKind"]): FetchResult => ({ url, status: 0, ok: false, contentType: "", headers: {}, setCookies: [], body: "", bytes: 0, sha256: hash(""), storedBytes: 0, storedHash: hash(""), receivedBytes: 0, complete: false, truncated: false, finalUrl: null, error, failureKind });
const describe = (e: unknown): string => e instanceof Error ? `${e.message}${e.cause ? `: ${describe(e.cause)}` : ""}` : String(e);
const agents = new Map<string, Dispatcher>();
export const httpDispatcher = (proxy: string | undefined, rejectUnauthorized = false, proxyRejectUnauthorized = true): Dispatcher | undefined => {
  // No proxy: ALWAYS defer to the live global dispatcher. Snapshotting the
  // global at module-load time is wrong twice over — a test MockAgent
  // installed before import makes the snapshot equal the mock (so the
  // "swapped" check passes and we build a REAL agent that bypasses it), and a
  // swap after import would keep us on a dead dispatcher. TLS-verify policy
  // for the no-proxy path is handled by the caller via options, not by
  // hijacking the global.
  if (!proxy) {
    if (rejectUnauthorized === false) return undefined;
    const key = JSON.stringify([proxy, rejectUnauthorized, proxyRejectUnauthorized]);
    let d = agents.get(key); if (d) return d;
    d = new Agent({ connect: { rejectUnauthorized } });
    agents.set(key, d); return d;
  }
  const key = JSON.stringify([proxy, rejectUnauthorized, proxyRejectUnauthorized]);
  let d = agents.get(key); if (d) return d;
  {
    const u = new URL(proxy);
    if (!["http:", "https:", "socks5:", "socks:"].includes(u.protocol)) throw new Error("unsupported proxy protocol");
    if (u.protocol.startsWith("socks")) d = new Socks5ProxyAgent(u, { requestTls: { rejectUnauthorized } } as ConstructorParameters<typeof Socks5ProxyAgent>[1]);
    else {
      const token = u.username || u.password ? `Basic ${Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64")}` : undefined;
      u.username = ""; u.password = "";
      d = new ProxyAgent({ uri: u.href, token, requestTls: { rejectUnauthorized }, proxyTls: { rejectUnauthorized: proxyRejectUnauthorized } });
    }
  }
  agents.set(key, d); return d;
};
const sleep = async (ms: number, signal?: AbortSignal): Promise<void> => {
  if (signal?.aborted) return;
  await new Promise<void>(resolve => {
    const done = (): void => { clearTimeout(t); signal?.removeEventListener("abort", done); resolve(); };
    const t = setTimeout(done, ms); signal?.addEventListener("abort", done, { once: true });
  });
};
const IDEMPOTENT = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);
export const fetchUrl = async (url: string, options: FetchOptions = {}): Promise<FetchResult> => {
  const signal = options.signal ?? executionSignal();
  let current = url; let settings = { ...options, signal, redirect: "manual" as const }; const jar = new SessionJar();
  for (let hop = 0; ; hop++) {
    const tries = Math.max(1, settings.maxAttempts ?? (IDEMPOTENT.has((settings.method ?? "GET").toUpperCase()) ? 3 : 1));
    let r: FetchResult;
    for (let attempt = 1; ; attempt++) {
      r = await fetchOnce(current, settings);
      const transient = r.failureKind === "transport-error" || r.status >= 500;
      if (!transient || attempt >= tries || signal?.aborted) break;
      await sleep(1000, signal);
    }
    if (r.status > 0) jar.update(current, r.setCookies ?? []);
    if (options.redirect !== "follow" || ![301, 302, 303, 307, 308].includes(r.status) || !r.headers.location || r.complete !== true) return { ...r, url, finalUrl: current };
    if (hop >= 10) return { ...r, url, ok: false, complete: false, error: "redirect limit", failureKind: "transport-error" };
    let next: URL; try { next = new URL(r.headers.location, current); if (!["http:", "https:"].includes(next.protocol)) throw new Error("unsupported redirect protocol"); }
    catch (e) { return { ...r, url, ok: false, complete: false, error: describe(e), failureKind: "invalid-request" }; }
    let headers = credentialScope(next.href, current, settings.headers);
    let cookie = new URL(current).origin === next.origin ? settings.cookie : undefined;
    const fromJar = jar.header(next.href); if (fromJar) cookie = cookie ? `${cookie}; ${fromJar}` : fromJar;
    let method = (settings.method ?? "GET").toUpperCase(); let body = settings.body;
    if ((r.status === 303 && method !== "HEAD") || ([301, 302].includes(r.status) && method === "POST")) { method = "GET"; body = undefined; delete headers["content-type"]; delete headers["content-length"]; }
    delete headers.host; current = next.href; settings = { ...settings, method, body, headers, cookie };
  }
};

const fetchOnce = async (url: string, options: FetchOptions): Promise<FetchResult> => {
  let u: URL;
  const method = (options.method ?? "GET").toUpperCase();
  const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;
  try {
    u = new URL(url);
    if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || !/^[!#$%&'*+.^_`|~0-9A-Z-]+$/.test(method) || method === "CONNECT" || !Number.isSafeInteger(maxBytes) || maxBytes < 0 || (["GET", "HEAD"].includes(method) && options.body !== undefined)) throw new Error("invalid request options");
    const checked = new Headers(options.headers); if (options.cookie) checked.set("cookie", options.cookie);
  } catch (e) { return failure(url, describe(e), "invalid-request"); }
  if (options.signal?.aborted) return failure(url, "request cancelled", "cancelled");
  const headers: Record<string, string> = { "user-agent": "velric-agent" };
  for (const [k, v] of Object.entries(options.headers ?? {})) headers[k.toLowerCase()] = v;
  if (options.cookie) headers.cookie = options.cookie;
  // Proxy authentication is transport configuration, never an origin header.
  delete headers["proxy-authorization"]; delete headers["proxy-connection"];
  const queued = new AbortController();
  const abortQueue = (): void => queued.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", abortQueue, { once: true });
  const queueTimer = options.queueTimeoutMs === undefined ? undefined : setTimeout(() => queued.abort("queue-timeout"), options.queueTimeoutMs);
  try { if (globalRps > 0) await acquire("network:global", { rps: globalRps, signal: queued.signal }).promise; }
  catch { return failure(url, "request cancelled while queued", options.signal?.aborted ? "cancelled" : "queue-timeout"); }
  finally { if (queueTimer) clearTimeout(queueTimer); options.signal?.removeEventListener("abort", abortQueue); }
  if (options.signal?.aborted) return failure(url, "request cancelled", "cancelled");
  const pool = options.proxy ? undefined : options.proxyPool ?? getProxyPool();
  const proxy = options.proxy ?? pool?.next() ?? undefined;
  if (pool && !proxy) return failure(url, "proxy pool exhausted", "proxy-exhausted");
  let dispatcher: Dispatcher | undefined;
  // Target-TLS relaxation only takes effect through the proxy path by design;
  // without a proxy the option keeps the process-global dispatcher (tests
  // inject a MockAgent there, and the direct path validates target certs).
  try { dispatcher = httpDispatcher(proxy, proxy ? (options.rejectUnauthorized ?? false) : options.rejectUnauthorized, options.proxyRejectUnauthorized ?? true); }
  catch (e) { if (proxy) pool?.reportFailure(proxy); return failure(url, describe(e), "invalid-request"); }
  const controller = new AbortController();
  const abort = (): void => controller.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort("network-timeout"), options.timeoutMs ?? 25000);
  let result: FetchResult; let sent = false;
  try {
    const underlying = dispatcher ?? getGlobalDispatcher();
    const observed = { dispatch(opts: Dispatcher.DispatchOptions, handler: Dispatcher.DispatchHandler): boolean {
      const wrapped = new Proxy(handler, { get(target, key) {
        const value = Reflect.get(target, key);
        if (key === "onConnect" || (key === "onRequestStart" && typeof value === "function")) return (...args: unknown[]) => { sent = true; return typeof value === "function" ? value.apply(target, args) : undefined; };
        return typeof value === "function" ? value.bind(target) : value;
      } });
      return underlying.dispatch(opts, wrapped);
    } } as Dispatcher;
    const req = { method, headers, body: options.body, signal: controller.signal, dispatcher: observed };
    const res = method === "TRACE" ? await (async () => {
      const r = await undiciRequest(url, { ...req, method: "TRACE" });
      const h = new Headers(); const cookies: string[] = [];
      for (const [k, v] of Object.entries(r.headers)) if (v !== undefined) for (const value of Array.isArray(v) ? v : [v]) { h.append(k, value); if (k === "set-cookie") cookies.push(value); }
      Object.defineProperty(h, "getSetCookie", { value: () => cookies });
      return { status: r.statusCode, ok: r.statusCode >= 200 && r.statusCode < 300, headers: h, url, body: r.body };
    })() : await undiciFetch(url, { ...req, redirect: options.redirect ?? "manual" });
    const chunks: Buffer[] = []; let storedBytes = 0; let receivedBytes = 0; let truncated = false; let error: string | undefined;
    try {
      if (res.body) for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        const c = Buffer.from(chunk); receivedBytes += c.length;
        const remaining = Math.max(0, maxBytes - storedBytes);
        if (remaining) { const part = c.subarray(0, remaining); chunks.push(part); storedBytes += part.length; }
        if (receivedBytes > maxBytes) { truncated = true; void (res.body as { destroy?: () => void })?.destroy?.(); break; }
      }
    } catch (e) { error = describe(e); }
    const buf = Buffer.concat(chunks, storedBytes); const sha256 = hash(buf); const complete = !truncated && !error;
    const responseHeaders: Record<string, string> = {}; res.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });
    result = { url, status: res.status, ok: res.ok && complete, contentType: res.headers.get("content-type") ?? "", headers: responseHeaders, setCookies: res.headers.getSetCookie(), body: options.raw ? "" : buf.toString("utf8"), rawBuffer: options.raw ? buf : undefined, bytes: storedBytes, sha256, storedBytes, storedHash: sha256, receivedBytes, complete, truncated, finalUrl: res.url || url, ...(error ? { error, failureKind: options.signal?.aborted ? "cancelled" : "transport-error" } : truncated ? { failureKind: "body-limit" } : {}) };
  } catch (e) { result = failure(url, describe(e), options.signal?.aborted ? "cancelled" : "transport-error"); }
  finally { clearTimeout(timer); options.signal?.removeEventListener("abort", abort); }
  if (proxy && pool) { if (result.failureKind === "transport-error") pool.reportFailure(proxy); else if (result.status > 0) pool.reportSuccess(proxy); }
  if (sent && executionRunId() !== "unbound") {
    const receipt = await recordReceipt({ url, method, status: result.status, requestHash: hash(JSON.stringify({ method, url, headers, body: options.body ?? null })), responseHash: result.storedHash, principal: principalHash(headers), complete: result.complete === true, finalUrl: result.finalUrl });
    result = { ...result, receiptId: receipt.id };
  }
  return result;
};
