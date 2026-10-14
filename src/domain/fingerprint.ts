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
  const [pair] = sc.split(";");
  const name = (pair ?? "").split("=")[0]?.trim() ?? "?";
  const lower = sc.toLowerCase();
  return {
    name,
    secure: lower.includes("secure"),
    httpOnly: lower.includes("httponly"),
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
  const putProbe = await fetchUrl(base, { ...opts, method: "PUT", body: "velric-probe" });
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

  const result = { baseUrl: base, waf: [...new Set(waf)], methods: { allowed, putWorks, traceWorks }, cookies, techHeaders };
  const path = join(input.outputRoot, "fingerprint.json");
  const body = JSON.stringify(result, null, 2);
  await writeFile(path, body);
  return { ...result, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
