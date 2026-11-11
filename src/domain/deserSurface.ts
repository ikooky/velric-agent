import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { charSimilarity, normalizeBody } from "./normalize.js";

/** Deserialization surface: where does the app accept a serialized object and
 *  try to parse it? Passive scan (serialized blobs already in cookies/params,
 *  ASP.NET ViewState without MAC) plus active differential injection of Java
 *  stream / PHP object / pickle / YAML-tag payloads per parameter and cookie.
 *  A parse-error signature or a 500 the baseline doesn't produce = the value
 *  reaches a deserializer. */

export interface DeserInput {
  readonly url: string;
  readonly outputRoot: string;
  readonly params?: readonly string[];
  readonly cookieName?: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export type DeserVerdict = "reaches-deserializer" | "parsed" | "rejected" | "unknown";

export interface DeserProbe {
  readonly carrier: string;
  readonly format: string;
  readonly status: number;
  readonly verdict: DeserVerdict;
  readonly evidence: string;
}

export interface DeserResult {
  readonly passive: { carrier: string; format: string; value: string }[];
  readonly viewState: { present: boolean; mac: boolean; eventValidation: boolean };
  readonly probes: DeserProbe[];
  readonly exploitable: readonly DeserProbe[];
  readonly artifacts: { path: string; bytes: number }[];
}

// Java serialized empty HashMap, PHP serialized stdClass, pickle protocol 4
// list, and a YAML python tag.
const PAYLOADS: { format: string; value: string }[] = [
  { format: "java", value: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAAAeA==" },
  { format: "php", value: 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}' },
  { format: "pickle", value: "gASVDQAAAAAAAABdlIwGdmVscmljlGEu" },
  { format: "yaml", value: '!!python/object/apply:os.system ["id"]' },
];

const ERROR_SIG = /(ClassNotFoundException|InvalidClassException|ObjectInputStream|java\.io\.|Unserialize|unserialize\(\)|Cannot deserialize|deserializ|pickle|UnpicklingError|SafeConstructor|ConstructorError|yaml\.|unknown object|__PHP_Incomplete_Class)/i;
const SERIALIZED_VALUE = [/^rO0AB/, /^O:\d+:/, /^a:\d+:/, /^gASV/, /^eyJ/];

export const probeDeser = async (input: DeserInput): Promise<DeserResult> => {
  const u = new URL(input.url);
  const cookieJar = (): Record<string, string> => (input.cookie ? { cookie: input.cookie } : {});
  const get = (url: string) => fetchUrl(url, { headers: cookieJar(), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024 });

  const passive: DeserResult["passive"] = [];
  for (const [name, value] of u.searchParams.entries()) {
    for (const re of SERIALIZED_VALUE) if (re.test(value)) { passive.push({ carrier: `query:${name}`, format: "serialized", value: value.slice(0, 60) }); break; }
  }
  // Cookie header/cookie set passed by the caller.
  const cookieText = input.cookie ?? "";
  for (const pair of cookieText.split(/;\s*/)) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const value = pair.slice(eq + 1);
    for (const re of SERIALIZED_VALUE) if (re.test(value)) { passive.push({ carrier: `cookie:${pair.slice(0, eq)}`, format: "serialized", value: value.slice(0, 60) }); break; }
  }

  const page = await get(u.href);
  const viewState = { present: /__VIEWSTATE/.test(page.body), mac: /__VIEWSTATEMAC/.test(page.body), eventValidation: /__EVENTVALIDATION/.test(page.body) };

  const probes: DeserProbe[] = [];
  const params = input.params?.length ? input.params : [...u.searchParams.keys()];
  const carriers: { carrier: string; build: (value: string) => string; send: (value: string) => Promise<{ status: number; body: string }> }[] = [];
  for (const p of params) {
    carriers.push({
      carrier: `query:${p}`,
      build: (v) => { const c = new URL(u.href); c.searchParams.set(p, v); return c.href; },
      send: async (v) => { const c = new URL(u.href); c.searchParams.set(p, v); const r = await get(c.href); return { status: r.status, body: r.body }; },
    });
  }
  if (input.cookieName) {
    carriers.push({
      carrier: `cookie:${input.cookieName}`,
      build: (v) => v,
      send: async (v) => { const cookie = input.cookie ? `${input.cookie}; ${input.cookieName}=${encodeURIComponent(v)}` : `${input.cookieName}=${encodeURIComponent(v)}`; const r = await fetchUrl(u.href, { headers: { cookie }, maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024 }); return { status: r.status, body: r.body }; },
    });
  }

  for (const c of carriers) {
    const baseline = await c.send("velric-baseline");
    const baseNorm = normalizeBody(baseline.body);
    for (const p of PAYLOADS) {
      const r = await c.send(p.value);
      const sig = ERROR_SIG.exec(r.body)?.[0];
      const sim = baseline.body ? charSimilarity(normalizeBody(r.body), baseNorm) : 0;
      let verdict: DeserVerdict = "unknown";
      let evidence = `${r.status}, sim ${sim.toFixed(2)}`;
      if (sig) { verdict = "reaches-deserializer"; evidence = `${r.status}, parser error "${sig}"`; }
      else if (baseline.status < 400 && r.status >= 500) { verdict = "reaches-deserializer"; evidence = `${r.status} on serialized input (baseline ${baseline.status})`; }
      else if (r.status === baseline.status && sim < 0.9) { verdict = "parsed"; evidence = `${r.status}, body changed (sim ${sim.toFixed(2)}) — value consumed`; }
      else if (r.status === baseline.status) { verdict = "rejected"; evidence = `${r.status}, no change`; }
      probes.push({ carrier: c.carrier, format: p.format, status: r.status, verdict, evidence });
      void c.build;
    }
  }

  const exploitable = probes.filter((p) => p.verdict === "reaches-deserializer");
  const body = JSON.stringify({ url: input.url, passive, viewState, probes, exploitable }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "deser_surface.json", body);
  return { passive, viewState, probes, exploitable, artifacts: [artifact] };
};
