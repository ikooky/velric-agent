import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Business-logic value abuse: numeric fields that accept out-of-domain
 *  values (negative quantities, zero prices, fractional stock, overflow,
 *  string-form numerics). A value is confirmed when the server both
 *  accepts it AND persists/echoes it — detected via response reflection
 *  or a post-write read-back. */

export interface ValueAbuseInput {
  readonly url: string;
  readonly method?: string;
  readonly bodyTemplate: string;
  /** numeric fields to test; auto-detect numbers in template if absent */
  readonly fields?: readonly string[];
  readonly outputRoot: string;
  /** verify persistence by re-reading (GET) after write */
  readonly verifyUrl?: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface VaCase {
  readonly field: string;
  readonly value: string;
  readonly kind: string;
  readonly status: number;
  readonly accepted: boolean;
  readonly echoed: boolean;
  readonly verified: boolean;
  readonly bodyPrefix: string;
}
export interface ValueAbuseResult {
  readonly probed: number;
  readonly confirmed: VaCase[];
  readonly leads: VaCase[];
  readonly cases: VaCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const VARIANTS: { kind: string; make: (n: number) => string }[] = [
  { kind: "negative", make: n => String(-Math.abs(n || 1) * 10) },
  { kind: "zero", make: () => "0" },
  { kind: "fractional", make: n => String((n || 1) / 2) },
  { kind: "overflow", make: () => "2147483648" },
  { kind: "bigint", make: () => "9007199254740993" },
  { kind: "string-numeric", make: n => JSON.stringify(n || 1) },
  { kind: "exp-notation", make: () => "1e3" },
];

export const probeValueAbuse = async (input: ValueAbuseInput): Promise<ValueAbuseResult> => {
  const method = input.method ?? "POST";
  let template: Record<string, unknown> = {};
  try { template = JSON.parse(input.bodyTemplate) as Record<string, unknown>; } catch { throw new Error("bodyTemplate must be JSON"); }
  const numFields = input.fields ?? Object.entries(template).filter(([, v]) => typeof v === "number").map(([k]) => k);
  const hdrs = { "content-type": "application/json", ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) };
  const send = async (body: string): Promise<{ status: number; body: string }> => {
    const r = await fetchUrl(input.url, { method, body, cookie: input.cookie, headers: hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
    return { status: r.status, body: r.body.slice(0, 2500) };
  };
  const readBack = async (): Promise<string> => {
    if (!input.verifyUrl) return "";
    const r = await fetchUrl(input.verifyUrl, { cookie: input.cookie, headers: hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
    return r.body.slice(0, 4000);
  };
  const cases: VaCase[] = [];
  const confirmed: VaCase[] = [];
  const leads: VaCase[] = [];
  for (const f of numFields) {
    const orig = template[f];
    for (const v of VARIANTS) {
      const val = v.make(typeof orig === "number" ? orig : 1);
      const rawVal = val.startsWith("\"") ? JSON.parse(val) as string : val;
      const body = JSON.stringify({ ...template, [f]: rawVal });
      const r = await send(body);
      const accepted = r.status >= 200 && r.status < 300;
      // 回显: 值本身出现在响应体(数值或字符串形式)
      const echoed = accepted && r.body.includes(String(rawVal));
      let verified = false;
      if (accepted && echoed && input.verifyUrl) {
        const rb = await readBack();
        verified = rb.includes(String(rawVal)) || rb.includes(`"${f}":${rawVal}`);
      }
      const c: VaCase = { field: f, value: val, kind: v.kind, status: r.status, accepted, echoed, verified, bodyPrefix: r.body.slice(0, 100) };
      cases.push(c);
      if (verified) confirmed.push(c);
      else if (accepted && echoed) leads.push(c);
    }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "value_abuse_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "value_abuse.md", [
      "# Business-logic value abuse",
      "",
      `confirmed: ${confirmed.length}, leads: ${leads.length}`,
      "",
      ...confirmed.map(c => `- **CONFIRMED ${c.field}=${c.value}** [${c.kind}] persisted (read-back verified)`),
      ...leads.map(c => `- lead ${c.field}=${c.value} [${c.kind}] accepted+echoed (persistence unverified)`),
    ].join("\n")),
  ];
  return { probed: cases.length, confirmed, leads, cases, artifacts };
};
