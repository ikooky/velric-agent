import { fetchUrl } from "../adapters/http.js";
import { normalizeBody, charSimilarity } from "./normalize.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** HTTP Parameter Pollution: duplicate/segmented parameters whose
 *  combined effect escapes single-value validation. Detects parsers
 *  that concatenate (Tomcat), last-wins (PHP), first-wins (ASP),
 *  array-cast (Rails) by response differential. */

export interface HppInput {
  readonly baseUrl: string;
  /** query params discovered via mine-params/merge-params */
  readonly params: readonly string[];
  readonly outputRoot: string;
  readonly expectedValue?: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface HppCase {
  readonly url: string;
  readonly param: string;
  readonly strategy: string;
  readonly payloadTail: string;
  readonly status: number;
  readonly bodyPrefix: string;
  readonly reflected: boolean;
}
export interface HppResult {
  readonly probed: number;
  /** params whose multi-value encoding changed the response semantics */
  readonly findings: { param: string; evidence: HppCase; baseline: HppCase; strategy: string; sim: number }[];
  readonly cases: HppCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const sig = async (u: string, cookie?: string, headers?: Record<string, string>, proxy?: string, timeoutMs?: number): Promise<{ status: number; body: string }> => {
  const r = await fetchUrl(u, { cookie, headers, proxy, timeoutMs: timeoutMs ?? 15000 });
  return { status: r.status, body: r.body.slice(0, 4000) };
};

export const probeHpp = async (input: HppInput): Promise<HppResult> => {
  const base = new URL(input.baseUrl);
  const strategies: { name: string; encode: (p: string, v1: string, v2: string) => string }[] = [
    { name: "duplicate", encode: (p, v1, v2) => `${p}=${encodeURIComponent(v1)}&${p}=${encodeURIComponent(v2)}` },
    { name: "array-cast", encode: (p, v1, v2) => `${p}[]=${encodeURIComponent(v1)}&${p}[]=${encodeURIComponent(v2)}` },
    { name: "comma-split", encode: (p, v1, v2) => `${p}=${encodeURIComponent(v1 + "," + v2)}` },
    { name: "semicolon-split", encode: (p, v1, v2) => `${p}=${encodeURIComponent(v1 + ";" + v2)}` },
    { name: "percent-dot", encode: (p, v1, v2) => `${p}=${encodeURIComponent(v1)}%2E${encodeURIComponent(v2)}` },
  ];
  const v1 = input.expectedValue ?? "1";
  const v2 = "HPP_MARKER_2";
  const cases: HppCase[] = [];
  // baseline: single value
  const baseQ = base.searchParams.toString();
  const baselineBody = await sig(input.baseUrl, input.cookie, input.headers, input.proxy, input.timeoutMs);
  cases.push({ url: input.baseUrl, param: "(baseline)", strategy: "single", payloadTail: baseQ, status: baselineBody.status, bodyPrefix: baselineBody.body.slice(0, 120), reflected: baselineBody.body.includes("HPP_MARKER_2") });
  const findings: HppResult["findings"] = [];
  for (const p of input.params) {
    for (const st of strategies) {
      const u = new URL(input.baseUrl);
      u.search = "";
      const keep = new URL(input.baseUrl).searchParams;
      const parts: string[] = [];
      for (const [k, v] of keep.entries()) if (k !== p) parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
      parts.push(st.encode(p, v1, v2));
      u.search = "?" + parts.join("&");
      const r = await sig(u.toString(), input.cookie, input.headers, input.proxy, input.timeoutMs);
      const c: HppCase = { url: u.toString(), param: p, strategy: st.name, payloadTail: parts.slice(-1)[0] ?? "", status: r.status, bodyPrefix: r.body.slice(0, 120), reflected: r.body.includes("HPP_MARKER_2") };
      cases.push(c);
      const sim = charSimilarity(normalizeBody(baselineBody.body), normalizeBody(r.body));
      // 同参数基线差异显著 + 第二值被反射/或语义变化(405→200等) = 污染生效
      if (r.body.includes("HPP_MARKER_2") || (sim < 0.92 && r.status !== baselineBody.status)) {
        findings.push({ param: p, evidence: c, baseline: { url: input.baseUrl, param: p, strategy: "single", payloadTail: v1, status: baselineBody.status, bodyPrefix: baselineBody.body.slice(0, 120), reflected: false }, strategy: st.name, sim });
      }
    }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "hpp_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "hpp_findings.md", ["# HPP findings", "", ...findings.map(f => `- **${f.param}** [${f.strategy}] sim=${f.sim.toFixed(3)} — marker reflected: \`${f.evidence.reflected}\`, status ${f.baseline.status}→${f.evidence.status}\n  - ${f.evidence.url.slice(0, 160)}`)].join("\n")),
  ];
  return { probed: input.params.length * strategies.length, findings, cases, artifacts };
};
