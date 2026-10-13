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
  let dispatcher: ProxyAgent | Socks5ProxyAgent | undefined;
  if (options.proxy) {
    dispatcher = options.proxy.startsWith("socks5")
      ? new Socks5ProxyAgent(new URL(options.proxy))
      : new ProxyAgent({ uri: options.proxy, connect: { rejectUnauthorized: false } });
  }

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
    const buf = Buffer.from(await res.arrayBuffer());
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