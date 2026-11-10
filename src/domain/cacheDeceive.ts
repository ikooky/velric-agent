import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Web cache deception/poisoning surface probe:
 *  1) path suffix tricks (/api/me/nonexist.css) that make caches store
 *     authenticated content publicly (Web Cache Deception)
 *  2) unkeyed header injection surface (X-Forwarded-Host reflected into
 *     response → cache poisoning candidate) */

export interface CacheInput {
  readonly baseUrl: string;
  /** authenticated page that returns user-private content */
  readonly privatePath?: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface CacheCase {
  readonly url: string;
  readonly trick: string;
  readonly status: number;
  readonly length: number;
  readonly contentType: string;
  readonly cacheable: boolean;
  readonly authContent: boolean;
}
export interface CacheResult {
  readonly probed: number;
  readonly deceptionSuspects: CacheCase[];
  readonly poisonSurface: { header: string; reflected: boolean; inCachingHeader: boolean; evidence: string }[];
  readonly cases: CacheCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const SUFFIXES = ["css", "js", "png", "jpg", "ico", "svg", "txt", "json.orig", "woff2", "map"];

export const probeCache = async (input: CacheInput): Promise<CacheResult> => {
  const priv = input.privatePath ?? "/api/me";
  const base = input.baseUrl.replace(/\/$/, "");
  const cases: CacheCase[] = [];
  const deceptionSuspects: CacheCase[] = [];
  // 基线: 私有内容特征(带cookie请求 /api/me 的正文指纹)
  const base1 = await fetchUrl(`${base}${priv}`, { cookie: input.cookie, headers: input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
  const authMarker = base1.body.slice(0, 200);
  for (const suf of SUFFIXES) {
    for (const joiner of ["/", "."]) {
      const u = `${base}${priv}${joiner}probe-nonexistent-${Date.now() % 10000}.${suf}`;
      const r = await fetchUrl(u, { cookie: input.cookie, headers: input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
      const cc = r.headers["cache-control"] ?? "";
      const cacheable = !/no-store|private|no-cache/i.test(cc) && (r.headers["age"] !== undefined || /max-age=[1-9]/.test(cc));
      // 私有内容在后缀路径仍返回200且正文≈私有正文 → 缓存欺骗候选
      const authContent = r.status === 200 && r.body.slice(0, 200) === authMarker && authMarker.length > 0;
      const c: CacheCase = { url: u, trick: `${joiner}${suf}`, status: r.status, length: r.bytes, contentType: r.contentType, cacheable, authContent };
      cases.push(c);
      if (authContent) deceptionSuspects.push(c);
    }
  }
  // 匿名复查: 候选路径不带cookie再取 — 若仍回私有内容, 缓存已投毒(或本就公开)
  const confirmed: CacheCase[] = [];
  for (const s of deceptionSuspects) {
    const r = await fetchUrl(s.url, { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
    if (r.status === 200 && r.body.slice(0, 200) === authMarker) confirmed.push(s);
  }
  // unkeyed header surface: X-Forwarded-Host / X-Forwarded-Scheme 反射
  const poisonSurface: CacheResult["poisonSurface"] = [];
  for (const [h, v] of [["x-forwarded-host", "poison-probe.example"], ["x-forwarded-scheme", "nope"], ["x-original-host", "poison-probe.example"], ["x-host", "poison-probe.example"], ["x-rewrite-url", "/poisoned"], ["x-forwarded-server", "poison-probe.example"]] as [string, string][]) {
    const r = await fetchUrl(base1.url, { headers: { ...(input.headers ?? {}), [h]: v }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
    const bodyHit = r.body.includes(v);
    const headerHit = Object.entries(r.headers).some(([, hv]) => String(hv).includes(v));
    if (bodyHit || headerHit) poisonSurface.push({ header: h, reflected: bodyHit, inCachingHeader: headerHit, evidence: bodyHit ? `value reflected in body (${r.bytes}B)` : `value reflected in response header` });
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "cache_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "cache_findings.md", [
      "# Web cache deception / poisoning surface",
      "",
      `## Cache deception (private=${priv}${confirmed.length ? `, 匿名复核仍返回私有内容: ${confirmed.length} 条` : ""})`,
      ...(deceptionSuspects.length ? deceptionSuspects.map(s => `- **${s.url}** [${s.trick}] ${s.status} cacheable=${s.cacheable}${confirmed.includes(s) ? " ← **匿名可取=已污染**" : ""}`) : ["- 无后缀命中私有内容"]),
      "",
      "## Unkeyed header surface",
      ...(poisonSurface.length ? poisonSurface.map(p => `- **${p.header}** — ${p.evidence}`) : ["- 无反射"]),
    ].join("\n")),
  ];
  return { probed: cases.length, deceptionSuspects: confirmed, poisonSurface, cases, artifacts };
};
