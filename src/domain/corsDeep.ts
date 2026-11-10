import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Deep CORS exploitability: reflection matrix (origin patterns × credentialed
 *  requests × HTTP methods), preflight handling, null-origin acceptance,
 *  wildcard-with-credentials (spec violation), and subdomain wildcard that
 *  accepts attacker-controllable siblings. */

export interface CorsDeepInput {
  readonly url: string;
  readonly outputRoot: string;
  /** candidate sibling subdomains that could be attacker-controlled */
  readonly subdomains?: readonly string[];
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface CorsCase {
  readonly origin: string;
  readonly reflectOrigin: boolean;
  readonly allowCredentials: boolean;
  readonly acam: string | null;
  readonly verdict: "exploitable-arbitrary" | "exploitable-null" | "exploitable-sibling" | "reflect-no-creds" | "safe";
}
export interface CorsDeepResult {
  readonly probed: number;
  readonly exploitable: CorsCase[];
  readonly preflightMethods: string | null;
  readonly cases: CorsCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const originsFor = (host: string, subs: readonly string[]): string[] => {
  const evil = "https://attacker-velric.example";
  const sibling = subs.length > 0 ? `https://${subs[0]}.${host}` : `https://sibling-probe.${host}`;
  return [evil, "null", evil + ".", `https://${host}.attacker-velric.example`, sibling, `https://evil-velric.example#${host}`];
};

export const probeCorsDeep = async (input: CorsDeepInput): Promise<CorsDeepResult> => {
  const u = new URL(input.url);
  const origins = originsFor(u.hostname, input.subdomains ?? []);
  const cases: CorsCase[] = [];
  const exploitable: CorsCase[] = [];
  for (const o of origins) {
    try {
      const r = await fetchUrl(input.url, { headers: { ...input.headers, origin: o }, cookie: input.cookie, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 });
      const acao = r.headers["access-control-allow-origin"] ?? null;
      const acac = r.headers["access-control-allow-credentials"] ?? "";
      const acam = r.headers["access-control-allow-methods"] ?? null;
      const reflectOrigin = acao === o || acao === "*";
      const allowCredentials = acac.toLowerCase() === "true";
      const isNull = o === "null";
      const isSibling = o.endsWith("." + u.hostname);
      let verdict: CorsCase["verdict"] = "safe";
      if (acao === o && allowCredentials) verdict = isNull ? "exploitable-null" : isSibling ? "exploitable-sibling" : "exploitable-arbitrary";
      else if (reflectOrigin) verdict = "reflect-no-creds";
      const c: CorsCase = { origin: o, reflectOrigin, allowCredentials, acam, verdict };
      cases.push(c);
      if (verdict.startsWith("exploitable")) exploitable.push(c);
    } catch { cases.push({ origin: o, reflectOrigin: false, allowCredentials: false, acam: null, verdict: "safe" }); }
  }
  // preflight
  let preflightMethods: string | null = null;
  try {
    const r = await fetchUrl(input.url, { method: "OPTIONS", headers: { ...input.headers, origin: "https://attacker-velric.example", "access-control-request-method": "PUT", "access-control-request-headers": "content-type,authorization" }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 });
    preflightMethods = r.headers["access-control-allow-methods"] ?? null;
  } catch { /* none */ }
  const artifacts = [
    await writeArtifact(input.outputRoot, "cors_deep.json", JSON.stringify({ cases, preflightMethods }, null, 2)),
    await writeArtifact(input.outputRoot, "cors_deep.md", ["# CORS deep", "", ...cases.map(c => `- \`${c.origin}\` → ACAO=${c.reflectOrigin ? "reflect" : "no"} creds=${c.allowCredentials} **${c.verdict}**`), "", `preflight methods: ${preflightMethods ?? "n/a"}`].join("\n")),
  ];
  return { probed: cases.length, exploitable, preflightMethods, cases, artifacts };
};
