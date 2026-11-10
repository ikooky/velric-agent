import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** SSTI (server-side template injection) surface: engine-agnostic canary
 *  arithmetic ({{7*7}}, ${7*7}, <%= 7*7 %>, #set, {7*7}, #{7*7}) with
 *  reflection check for the evaluated product 49. Confirmed = 49 appears
 *  in response while canary literal does not appear verbatim. */

export interface SstiInput {
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
export interface SstiCase {
  readonly engine: string;
  readonly payload: string;
  readonly status: number;
  readonly evaluated: boolean;
  readonly literalEcho: boolean;
  readonly bodyPrefix: string;
}
export interface SstiResult {
  readonly probed: number;
  readonly confirmed: SstiCase[];
  readonly cases: SstiCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const PAYLOADS: { engine: string; p: string }[] = [
  { engine: "jinja2/twig-handlebars", p: "{{7*7}}" },
  { engine: "twig-block", p: "{{ 7*7 }}" },
  { engine: "freemarker", p: "<#assign x=7*7>${x}" },
  { engine: "velocity", p: "#set($x=7*7)$x" },
  { engine: "smarty", p: "{7*7}" },
  { engine: "erb-ruby", p: "<%= 7*7 %>" },
  { engine: "es6-template", p: "${7*7}" },
  { engine: "mvel-ognl", p: "#{7*7}" },
  { engine: "pebble-thymeleaf", p: "@{(7*7)}" },
  { engine: "jinja-tuple-trick", p: "{{\"7\"*7}}1111111" },
  { engine: "nunjucks-ejs", p: "<%= 7*7 %>{{7*7}}" },
];

export const probeSsti = async (input: SstiInput): Promise<SstiResult> => {
  const method = input.method ?? (input.in === "body" ? "POST" : "GET");
  const where = input.in ?? "query";
  const hdrs = { ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) };
  const send = async (payload: string): Promise<{ status: number; body: string }> => {
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
    return { status: r.status, body: r.body };
  };
  const cases: SstiCase[] = [];
  const confirmed: SstiCase[] = [];
  for (const { engine, p } of PAYLOADS) {
    try {
      const r = await send(p);
      const evaluated = r.body.includes("49") || r.body.includes("1111111");
      const literalEcho = r.body.includes(p);
      const c: SstiCase = { engine, payload: p, status: r.status, evaluated, literalEcho, bodyPrefix: r.body.slice(0, 100) };
      cases.push(c);
      if (evaluated && !literalEcho) confirmed.push(c);
    } catch { /* transport */ }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "ssti_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "ssti_findings.md", ["# SSTI", "", `confirmed: ${confirmed.length}`, "", ...confirmed.map(c => `- **CONFIRMED [${c.engine}]** \`${c.payload}\` evaluated server-side (49 reflected)`)].join("\n")),
  ];
  return { probed: cases.length, confirmed, cases, artifacts };
};
