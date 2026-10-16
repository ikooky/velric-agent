import { tlsCertificate } from "../domain/tlsAudit.js";

import { fetchUrl } from "../adapters/http.js";

const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;

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
  /** TLS peer certificate SANs (subdomain discovery bycatch). */
  readonly tlsSans: string[];
  /** Present security headers (hsts/csp/etc). */
  readonly securityHeaders: Record<string, string>;
  /** Lightweight tech-stack signature from headers + body markers. */
  readonly techStack: string[];
  readonly error?: string;
  readonly complete?: boolean;
  readonly truncated?: boolean;
  readonly tlsError?: string;
  readonly receiptId?: string;
}

const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
] as const;

const TECH_MARKERS: ReadonlyArray<readonly [string, RegExp]> = [
  ["react", /(?:\/_next\/static|__NEXT_DATA__|data-reactroot)/],
  ["vue", /(?:\/_nuxt\/|__NUXT__|data-v-[0-9a-f]{8})/],
  ["svelte", /(?:svelte-[0-9a-z]{6}|__sveltekit)/],
  ["angular", /(?:ng-version=|angular\.min\.js|_ngcontent)/],
  ["jquery", /jquery[.-]?[0-9.]*\.min\.js|(?:window\.)?\$\.ajax/],
  ["webpack", /(?:webpackJsonp|__webpack_require__|\/static\/chunks\/)/],
  ["vite", /(?:\/assets\/index-[0-9A-Za-z_-]{8}\.js|import\.meta\.env)/],
  ["cloudflare", /(?:__cf_bm|cf-ray|cdn-cgi\/)/i],
  ["discourse", /(?:discourse|\/uploads\/default\/original)/i],
  ["wordpress", /(?:wp-content|wp-json|xmlrpc\.php)/i],
  ["discuz", /discuz/i],
  ["nginx", /^nginx\b/i],
  ["apache", /^(?:apache|httpd)/i],
  ["tomcat", /(?:tomcat|jboss|\/manager\/html)/i],
  ["iis", /(?:iis|microsoft-iis|x-aspnet)/i],
  ["spring", /(?:x-application-context|whitelabel error page)/i],
  ["shiro", /rememberMe=|JSESSIONID=/i],
  ["fastjson", /com\.alibaba\.fastjson/i],
];


/** One probe: status line, title, fingerprint headers, TLS SANs, tech stack. */
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
  readonly signal?: AbortSignal;
  readonly rejectUnauthorized?: boolean;
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
    signal: input.signal, rejectUnauthorized: input.rejectUnauthorized,
  });
  const titleMatch = res.body.match(TITLE_RE);
  const title = titleMatch
    ? titleMatch[1]!.replace(/\s+/g, " ").trim().slice(0, 200)
    : null;

  const techStack = new Set<string>();
  for (const [name, re] of TECH_MARKERS) {
    if (re.test(res.body) || (name === "nginx" && re.test(res.headers["server"] ?? "")) ||
        (name === "apache" && re.test(res.headers["server"] ?? ""))) {
      techStack.add(name);
    }
  }
  if (res.headers["x-powered-by"]) techStack.add(`powered:${res.headers["x-powered-by"]}`.slice(0, 40));
  if (res.headers["server"]) techStack.add(`server:${res.headers["server"]}`.slice(0, 40));

  const securityHeaders: Record<string, string> = {};
  for (const h of SECURITY_HEADERS) {
    const v = res.headers[h];
    if (v) securityHeaders[h] = v.slice(0, 200);
  }

  let tlsSans: string[] = [];
  let tlsError: string | undefined;
  // A malformed URL must degrade to "no TLS info", not throw past the
  // never-throw fetch contract.
  let u: URL | null = null;
  try { u = new URL(input.url); } catch { u = null; }
  if (u && u.protocol === "https:") {
    const cert = await tlsCertificate(u, { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 5000, signal: input.signal, rejectUnauthorized: input.rejectUnauthorized }).catch(e => { tlsError = e instanceof Error ? e.message : String(e); return null; });
    if (cert?.subject?.CN) tlsSans.push(`CN:${cert.subject.CN}`);
    const sans = (cert as unknown as { subjectaltname?: string })?.subjectaltname;
    if (sans) {
      tlsSans.push(
        ...sans.split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter((s) => s && !s.startsWith("IP:")).slice(0, 50),
      );
    }
  }

  return {
    url: input.url,
    finalUrl: res.finalUrl ?? null,
    complete: res.complete, truncated: res.truncated, receiptId: res.receiptId,
    ...(tlsError ? { tlsError } : {}),
    status: res.status,
    ok: res.ok,
    contentType: res.contentType,
    title,
    server: res.headers["server"] ?? null,
    poweredBy: res.headers["x-powered-by"] ?? null,
    bytes: res.bytes,
    elapsedMs: Date.now() - started,
    sha256: res.sha256 || null,
    tlsSans: [...new Set(tlsSans)].slice(0, 50),
    securityHeaders,
    techStack: [...techStack],
    ...(res.error ? { error: res.error } : {}),
  };
};
