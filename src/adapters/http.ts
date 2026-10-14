import { createHash } from "node:crypto";
import { ProxyAgent, Socks5ProxyAgent, fetch as undiciFetch, type Dispatcher } from "undici";

// Process-wide rate limiting (per-host token bucket) — opt-in via
// setGlobalRateLimit() so batch/targeted tools stay polite.
import { acquire } from "../domain/rateLimit.js";

let globalRps = 0;
export const setGlobalRateLimit = (rps: number): void => { globalRps = rps; };

/** Best-effort HTTP layer shared by probes and harvesters. TLS verification is
 * disabled on purpose: recon targets are often self-signed / internal hosts. */

export interface FetchOptions {
  readonly raw?: boolean;
  readonly redirect?: "follow" | "manual";
  readonly headers?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
  readonly proxy?: string;
  readonly cookie?: string;
  readonly maxBytes?: number;
  readonly method?: string;
  readonly body?: string;
}

export interface FetchResult {
  readonly url: string;
  readonly finalUrl?: string | null;
  readonly status: number;
  readonly ok: boolean;
  readonly contentType: string;
  readonly headers: Record<string, string>;
  readonly body: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly rawBuffer?: Buffer;
  readonly error?: string;
}

const DEFAULT_UA = "Mozilla/5.0 (velric-recon)";

export const fetchUrl = async (
  url: string,
  options: FetchOptions = {},
): Promise<FetchResult> => {
  // Default retry policy: initial + 2 retries on transient failures
  // (network errors, timeouts, 5xx), 1s backoff — user-wide convention.
  const maxAttempts = 3;
  let last: FetchResult | undefined;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const r = await fetchOnce(url, options);
    const transient =
      r.status === 0 ||        // network error / timeout / TLS reset
      r.status >= 500;         // server-side
    if (!transient || attempt === maxAttempts) return r;
    last = r;
    await new Promise((res) => setTimeout(res, 1000));
  }
  return last!;
};

// Per-proxy agent pool: reuses keep-alive agents instead of one per call.
const proxyAgentPool = new Map<string, ProxyAgent | Socks5ProxyAgent>();
const getProxyDispatcher = (proxyUri: string): ProxyAgent | Socks5ProxyAgent => {
  let d = proxyAgentPool.get(proxyUri);
  if (!d) {
    d = proxyUri.startsWith("socks5")
      ? new Socks5ProxyAgent(new URL(proxyUri))
      : new ProxyAgent({ uri: proxyUri, connect: { rejectUnauthorized: false } });
    proxyAgentPool.set(proxyUri, d);
  }
  return d;
};

const fetchOnce = async (
  url: string,
  options: FetchOptions = {},
): Promise<FetchResult> => {
  const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 25000);
  const headers: Record<string, string> = {
    "User-Agent": DEFAULT_UA,
    ...(options.headers ?? {}),
  };
  if (options.cookie) headers["Cookie"] = options.cookie;

  // A real egress proxy: requests route through it. Never leaked to the target.
  // Agents are pooled per proxy URI (keep-alive sockets are reused instead
  // of leaking one agent — and its socket set — per request).
  const dispatcher = options.proxy ? getProxyDispatcher(options.proxy) : undefined;

  // Per-host throttle when a global rate limit is configured.
  if (globalRps > 0) {
    try { await acquire(new URL(url).hostname, { rps: globalRps }); } catch { /* unthrottled */ }
  }
  try {
    const res = await undiciFetch(url, {
      method: options.method ?? "GET",
      headers,
      body: options.body,
      redirect: options.redirect ?? "follow",
      signal: controller.signal,
      ...(dispatcher ? { dispatcher } : {}),
    } satisfies Parameters<typeof undiciFetch>[1] & {
      dispatcher?: Dispatcher;
    });
    const finalRedirect = res.headers.get("location");
    // Skip oversized bodies early (declared size) instead of buffering them.
    const declared = Number(res.headers.get("content-length") ?? 0);
    if (declared > maxBytes * 4) {
      const headerObj: Record<string, string> = {};
      res.headers.forEach((v, k) => { headerObj[k.toLowerCase()] = v; });
      try { await res.body?.cancel(); } catch { /* already gone */ }
      return { url, status: res.status, ok: res.ok, contentType: res.headers.get("content-type") ?? "", headers: headerObj, body: "", bytes: 0, sha256: createHash("sha256").update("").digest("hex"), finalUrl: finalRedirect ?? null };
    }
    // Stream-cap: works for chunked too (content-length absent) — read the
    // body incrementally and stop at the cap instead of buffering it all.
    const cap = maxBytes * 4;
    const bodyChunks: Buffer[] = [];
    let bodyLen = 0;
    let overCap = false;
    try {
      for await (const c of res.body as unknown as AsyncIterable<Buffer>) {
        bodyLen += c.length;
        if (bodyLen > cap) { overCap = true; break; }
        bodyChunks.push(c);
      }
    } catch { /* mid-stream abort after break is expected */ }
    if (overCap) { try { await res.body?.cancel(); } catch { /* gone */ } }
    const buf = Buffer.concat(bodyChunks);
    const slice = buf.subarray(0, maxBytes);
    // raw mode: hand the caller the untouched Buffer (binary git objects etc.)
    if (options.raw) {
      (res as unknown as { __rawBuffer?: Buffer }).__rawBuffer = slice;
    }
    const headerObj: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headerObj[k] = v;
    });
    return {
      url,
      status: res.status,
      ok: res.ok,
      rawBuffer: (res as unknown as { __rawBuffer?: Buffer }).__rawBuffer,
      contentType: res.headers.get("content-type") ?? "",
      headers: headerObj,
      body: options.raw ? "" : slice.toString("utf8"),
      bytes: buf.length,
      sha256: createHash("sha256").update(buf).digest("hex"),
      finalUrl: finalRedirect ?? null,
    };
  } catch (cause) {
    return {
      url,
      status: 0,
      ok: false,
      contentType: "",
      headers: {},
      body: "",
      bytes: 0,
      sha256: "",
      error: cause instanceof Error ? cause.message : String(cause),
    };
  } finally {
    clearTimeout(timer);
  }
};