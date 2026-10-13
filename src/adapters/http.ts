import { createHash } from "node:crypto";
import { ProxyAgent, fetch as undiciFetch, type Dispatcher } from "undici";

/** Best-effort HTTP layer shared by probes and harvesters. TLS verification is
 * disabled on purpose: recon targets are often self-signed / internal hosts. */

export interface FetchOptions {
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
  readonly status: number;
  readonly ok: boolean;
  readonly contentType: string;
  readonly headers: Record<string, string>;
  readonly body: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly error?: string;
}

const DEFAULT_UA = "Mozilla/5.0 (velric-recon)";

export const fetchUrl = async (
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
  let dispatcher: ProxyAgent | undefined;
  if (options.proxy) {
    dispatcher = new ProxyAgent({
      uri: options.proxy,
      connect: { rejectUnauthorized: false },
    });
  }

  try {
    const res = await undiciFetch(url, {
      method: options.method ?? "GET",
      headers,
      body: options.body,
      redirect: "follow",
      signal: controller.signal,
      ...(dispatcher ? { dispatcher } : {}),
    } satisfies Parameters<typeof undiciFetch>[1] & {
      dispatcher?: Dispatcher;
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const slice = buf.subarray(0, maxBytes);
    const headerObj: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headerObj[k] = v;
    });
    return {
      url,
      status: res.status,
      ok: res.ok,
      contentType: res.headers.get("content-type") ?? "",
      headers: headerObj,
      body: slice.toString("utf8"),
      bytes: buf.length,
      sha256: createHash("sha256").update(buf).digest("hex"),
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