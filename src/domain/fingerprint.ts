import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** WAF/CDN identification (header fingerprint library) + HTTP method
 *  enumeration (OPTIONS/Allow + PUT/TRACE probes) + cookie security audit
 *  (Secure/HttpOnly/SameSite). Three small probes sharing one fetch. */

export interface FingerprintInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Opt in to the state-changing PUT probe (default: skipped). */
  readonly activeProbe?: boolean;
}

export interface FingerprintResult {
  readonly baseUrl: string;
  readonly waf: string[];
  readonly methods: { allowed: string[]; putWorks: boolean; traceWorks: boolean };
  readonly cookies: {
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string | null;
  }[];
  /** security-header audit + CSP evaluation + TLS audit (Wapiti-style). */
  readonly securityHeaders?: Record<string, { present: boolean; value?: string; note?: string }>;
  readonly missingHeaders?: string[];
  readonly cspFindings?: string[];
  readonly tls?: import("./tlsAudit.js").TlsAudit | null;
  readonly artifacts: { path: string; bytes: number }[];
}

/** Header fingerprints: [waf-name, header, value-re]. */
const WAF_SIGNATURES: ReadonlyArray<readonly [string, string, RegExp]> = [
  ["cloudflare", "server", /cloudflare/i],
  ["cloudflare", "cf-ray", /.*/],
  ["akamai", "server", /akamai/i],
  ["fastly", "server", /fastly/i],
  ["aws-waf", "x-amzn-requestid", /.*/],
  ["aws-waf", "x-amz-cf-id", /.*/],
  ["aliyun-waf", "server", /tengine/i],
  ["aliyun-waf", "x-swift", /.*/],
  ["qcloud-waf", "server", /sqr/i],
  ["qcloud-waf", "x-nws-log-uuid", /.*/],
  ["baidu-yunjia", "server", /yunjiasu/i],
  ["chuangyu", "server", /jiasule/i],
  ["safedog", "x-powered-by", /safedog|waf/i],
  ["baota", "server", /bt[_-]?(?:waf|firewall)/i],
  ["bce-cdn", "server", /bce?[-_]?(?:cdn|bcbrot)/i],
  ["qiniu-cdn", "x-qiniu-zone", /.*/],
  ["wangsu", "server", /wscd/i],
  ["knownsec", "server", /jiasule/i],
  ["modsecurity", "server", /mod_security/i],
];

const parseSetCookie = (sc: string): { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null } => {
  const parts = sc.split(";");
  const name = (parts[0] ?? "").split("=")[0]?.trim() ?? "?";
  // Attribute flags must match in the ATTRIBUTE segment (after the first
  // semicolon) — a cookie named "secureSession" or Path=/secure is NOT a
  // Secure cookie. Match whole attribute names, not substrings.
  const attrs = parts.slice(1).map((p) => p.trim().toLowerCase());
  return {
    name,
    secure: attrs.some((a) => a === "secure"),
    httpOnly: attrs.some((a) => a === "httponly"),
    sameSite: (sc.match(/samesite\s*=\s*(\w+)/i)?.[1] ?? null),
  };
};

export const fingerprint = async (input: FingerprintInput): Promise<FingerprintResult> => {
  const base = input.baseUrl.startsWith("http") ? input.baseUrl : `https://${input.baseUrl}`;
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { cookie: input.cookie, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10000 };

  const r = await fetchUrl(base, opts);
  const waf: string[] = [];
  for (const [name, header, re] of WAF_SIGNATURES) {
    const v = r.headers[header];
    if (v && re.test(v)) waf.push(name);
  }

  // Method enumeration on the base URL
  const opt = await fetchUrl(base, { ...opts, method: "OPTIONS" });
  const allow = opt.headers["allow"] ?? "";
  const allowed = allow.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
  // PUT is a state-changing request — sent only on explicit opt-in.
  const putProbe = (input as { activeProbe?: boolean }).activeProbe === true
    ? await fetchUrl(base, { ...opts, method: "PUT", body: "velric-probe" })
    : { status: 0, body: "", headers: {} as Record<string, string> };
  const putWorks = putProbe.status >= 200 && putProbe.status < 300;
  // TRACE acceptance check only (echo reflection would need a distinguishing
  // header token; undici fetch drops method-specific echo bodies reliably).
  const traceProbe = await fetchUrl(base, { ...opts, method: "TRACE", headers: { "x-velric-probe": "1" } });
  const traceEchoes = traceProbe.body.includes("x-velric-probe") || traceProbe.body.includes("X-Velric-Probe");
  const traceAllows = allow.includes("TRACE") || (traceProbe.headers["allow"] ?? "").includes("TRACE");
  const traceWorks = traceProbe.status === 200 && traceAllows && traceEchoes;

  // Cookies from the main response
  const sc = r.headers["set-cookie"];
  const cookies = sc
    ? (Array.isArray(sc) ? sc : [sc]).map(parseSetCookie)
    : [];

  // Tech-stack headers (Server / X-Powered-By / CDN hints) — part of the
  // fingerprint deliverable.
  const techHeaders: Record<string, string> = {};
  for (const k of ["server", "x-powered-by", "via", "x-aspnet-version", "x-generator", "x-drupal-cache", "x-vercel-id", "x-amz-cf-id", "x-served-by", "cf-ray"]) {
    const v = r.headers[k];
    if (typeof v === "string" && v.length > 0) techHeaders[k] = v;
  }

  // Security-header audit (Wapiti-style): presence + value sanity of the
  // OWASP recommended response headers.
  const securityHeaders: Record<string, { present: boolean; value?: string; note?: string }> = {};
  const expect = (h: string, note: string): void => {
    const v = r.headers[h];
    securityHeaders[h] = v ? { present: true, value: v.slice(0, 200) } : { present: false, note };
  };
  expect("strict-transport-security", "missing HSTS — protocol downgrade space");
  expect("x-frame-options", "missing XFO — clickjacking space (or use CSP frame-ancestors)");
  expect("x-content-type-options", "missing nosniff — MIME confusion space");
  expect("referrer-policy", "missing referrer policy — URL leakage via Referer");
  expect("content-security-policy", "missing CSP — injection containment absent");
  expect("permissions-policy", "missing permissions policy — powerful features ungated");
  const missingHeaders = Object.entries(securityHeaders).filter(([, v]) => !v.present).map(([k]) => k);

  // CSP mini-evaluator: parse the policy and flag weak directives.
  const csp = r.headers["content-security-policy"];
  const cspFindings: string[] = [];
  if (csp) {
    const policies = csp.split(";");
    for (const pol of policies) {
      const [dir, ...vals] = pol.trim().split(/\s+/);
      const d = (dir ?? "").toLowerCase();
      if (d === "default-src" || d === "script-src") {
        if (vals.includes("*")) cspFindings.push(`${d} includes wildcard *`);
        if (vals.some((v) => /(?:^|\.)example(?:d)?omain/i.test(v))) cspFindings.push(`${d} references example domain (template leftover)`);
      }
      if (d === "script-src" && vals.includes("'unsafe-inline'")) cspFindings.push("script-src allows 'unsafe-inline'");
      if (d === "script-src" && vals.includes("'unsafe-eval'")) cspFindings.push("script-src allows 'unsafe-eval'");
      if (d === "object-src" && vals.includes("'none'")) cspFindings.push("object-src 'none' (good)"); // positive marker
      if (d === "upgrade-insecure-requests") cspFindings.push("upgrade-insecure-requests present (good)");
    }
    if (!policies.some((p) => /^default-src/i.test(p.trim()))) cspFindings.push("no default-src fallback directive");
  }

  // TLS config audit: protocol versions + cert validity + weak ciphers via
  // node:tls (sslscan-lite). Only for https targets.
  let tls: FingerprintResult["tls"] = null;
  if (base.startsWith("https://")) {
    const { connectTlsAudit } = await import("./tlsAudit.js");
    tls = await connectTlsAudit(new URL(base));
  }

  const result = { baseUrl: base, waf: [...new Set(waf)], methods: { allowed, putWorks, traceWorks }, cookies, techHeaders, securityHeaders, missingHeaders, cspFindings, tls };
  const path = join(input.outputRoot, "fingerprint.json");
  const body = JSON.stringify(result, null, 2);
  await writeFile(path, body);
  return { ...result, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
