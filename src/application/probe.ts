import { fetchUrl } from "../adapters/http.js";

const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;

const TECH_HINTS: ReadonlyArray<readonly [string, string]> = [
  ["x-powered-by", "header"],
  ["server", "header"],
];

export interface ProbeResult {
  readonly url: string;
  readonly finalUrl: string | null;
  readonly status: number;
  readonly ok: boolean;
  readonly contentType: string;
  readonly title: string | null;
  readonly server: string | null;
  readonly poweredBy: string | null;
  readonly bytes: number;
  readonly elapsedMs: number;
  readonly sha256: string | null;
  readonly error?: string;
}

/** One probe: status line, title, fingerprint headers, body hash. */
export const httpProbe = async (input: {
  readonly url: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly redirect?: "follow" | "manual";
  readonly method?: string;
  readonly body?: string;
}): Promise<ProbeResult> => {
  const started = Date.now();
  const res = await fetchUrl(input.url, {
    cookie: input.cookie,
    proxy: input.proxy,
    timeoutMs: input.timeoutMs,
    maxBytes: input.maxBytes,
    headers: input.headers,
    redirect: input.redirect,
    method: input.method,
    body: input.body,
  });
  const titleMatch = res.body.match(TITLE_RE);
  const title = titleMatch
    ? titleMatch[1]!.replace(/\s+/g, " ").trim().slice(0, 200)
    : null;
  return {
    url: input.url,
    finalUrl: res.headers["location"] ?? null,
    status: res.status,
    ok: res.ok,
    contentType: res.contentType,
    title,
    server: res.headers["server"] ?? null,
    poweredBy: res.headers["x-powered-by"] ?? null,
    bytes: res.bytes,
    elapsedMs: Date.now() - started,
    sha256: res.sha256 || null,
    ...(res.error ? { error: res.error } : {}),
  };
};

export const TECH_HINT_KEYS = TECH_HINTS.map(([h]) => h);