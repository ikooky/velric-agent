import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/** Auth-surface mapping: every discovered endpoint probed twice (anonymous
 *  vs authenticated when a cookie is supplied). The delta classifies the API
 *  surface into anonymous-reachable / auth-required / auth-ambiguous — the
 *  core deliverable of API recon. */

export interface AuthProbeInput {
  /** api_merged.txt / api_static.txt path, or file with one URL per line. */
  readonly endpointsFile: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly concurrency?: number;
  readonly maxEndpoints?: number;
}

export interface AuthProbeResult {
  readonly probed: number;
  readonly anonymous: { url: string; status: number }[];
  readonly authRequired: { url: string; anonStatus: number; authStatus: number | null }[];
  readonly ambiguous: { url: string; anonStatus: number; note: string }[];
  /** Edge/IP-level block: every probe returned the same 403/429 — not
   *  endpoint-level auth; retry with proxy or cookie before concluding. */
  readonly edgeBlocked: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const fingerprintResponse = (r: { status: number; bytes: number; body: string }): string =>
  `${r.status}:${r.bytes > 0 ? Math.round(Math.log2(r.bytes + 1)) : 0}:${(r.body.match(/"(?:code|message|error|msg)"\s*:\s*"?[^",}]{0,20}/) ?? [""])[0]}`;

export const probeAuth = async (input: AuthProbeInput): Promise<AuthProbeResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const raw = (await readFile(input.endpointsFile, "utf8"))
    .split("\n").map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//") && !l.startsWith("#"))
    // entries may carry "METHOD url" prefixes from runtime api lists
    .map((l) => l.replace(/^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+/i, ""));
  let urls = [...new Set(raw)].slice(0, input.maxEndpoints ?? 200);
  // Same-origin scoping: the auth surface we map is the TARGET's. Third-party
  // SDK endpoints (advertising/telemetry beacons) resolved from the list are
  // cross-origin noise — drop them unless explicitly the only content.
  if (urls.length > 3) {
    // registrable-domain scope (approximation: last two labels of the
    // hostname). auth.<same-site>.com stays in scope for www.<same-site>.com;
    // third-party SDK hosts are dropped.
    const MULTI_SUFFIX = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "com.cn", "com.tw", "com.hk", "co.jp", "co.kr", "co.in", "co.za", "com.sg", "com.my"]);
    const regDomain = (h: string): string => {
      const parts = h.split(".").filter(Boolean);
      if (parts.length >= 3 && MULTI_SUFFIX.has(parts.slice(-2).join("."))) return parts.slice(-3).join(".");
      return parts.slice(-2).join(".");
    };
    const origins = new Map<string, number>();
    for (const u of urls) {
      try { const o = regDomain(new URL(u).hostname); origins.set(o, (origins.get(o) ?? 0) + 1); } catch { /* skip */ }
    }
    const mainOrigin = [...origins.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
    if (mainOrigin) urls = urls.filter((u) => { try { return regDomain(new URL(u).hostname) === mainOrigin; } catch { return false; } });
  }

  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };
  const anonymous: AuthProbeResult["anonymous"] = [];
  const authRequired: AuthProbeResult["authRequired"] = [];
  const ambiguous: AuthProbeResult["ambiguous"] = [];

  const queue = [...urls];
  const worker = async (): Promise<void> => {
    while (queue.length > 0) {
      const u = queue.shift()!;
      let full: string;
      try {
        full = new URL(u).href;
      } catch {
        continue; // relative path without origin — unusable here
      }
      // GET only: safe read probes for surface classification.
      const anon = await fetchUrl(full, { ...opts, method: "GET" });
      if (anon.status === 0) continue;
      const anonOk = anon.status >= 200 && anon.status < 300;
      const anonAuthish = anon.status === 401 || anon.status === 403;
      const anonRedirect = anon.status >= 300 && anon.status < 400;

      if (!input.cookie) {
        // No cookie supplied: classify by anonymous response alone.
        // A 3xx (typically → login page) is an auth redirect, not anonymous
        // content; park it as ambiguous rather than inflating the anon set.
        if (anonRedirect) ambiguous.push({ url: full, anonStatus: anon.status, note: `auth redirect ${anon.status}` });
        else if (anonOk) anonymous.push({ url: full, status: anon.status });
        else if (anonAuthish) authRequired.push({ url: full, anonStatus: anon.status, authStatus: null });
        else ambiguous.push({ url: full, anonStatus: anon.status, note: `status ${anon.status}` });
        continue;
      }
      const auth = await fetchUrl(full, { ...opts, method: "GET", cookie: input.cookie });
      const authOk = auth.status >= 200 && auth.status < 300;
      if (anonOk) anonymous.push({ url: full, status: anon.status });
      else if (!anonOk && authOk) authRequired.push({ url: full, anonStatus: anon.status, authStatus: auth.status });
      else if (anonAuthish && !authOk) authRequired.push({ url: full, anonStatus: anon.status, authStatus: auth.status });
      else ambiguous.push({ url: full, anonStatus: anon.status, note: `anon=${anon.status} auth=${auth.status} fp=${fingerprintResponse(anon) === fingerprintResponse(auth) ? "same" : "diff"}` });
    }
  };
  await Promise.all(Array.from({ length: input.concurrency ?? 8 }, worker));

  const total = anonymous.length + authRequired.length + ambiguous.length;
  const statusTally = new Map<number, number>();
  for (const a of anonymous) statusTally.set(a.status, (statusTally.get(a.status) ?? 0) + 1);
  for (const a of authRequired) statusTally.set(a.anonStatus, (statusTally.get(a.anonStatus) ?? 0) + 1);
  for (const a of ambiguous) statusTally.set(a.anonStatus, (statusTally.get(a.anonStatus) ?? 0) + 1);
  const [dominantStatus, dominantCount] = [...statusTally.entries()].sort((a, b) => b[1] - a[1])[0] ?? [0, 0];
  const edgeBlocked = total >= 4 && dominantCount / total >= 0.8 && (dominantStatus === 403 || dominantStatus === 429);

  const body = JSON.stringify({
    probed: total,
    edgeBlocked,
    anonymous: anonymous.sort((a, b) => a.url.localeCompare(b.url)),
    authRequired: authRequired.sort((a, b) => a.url.localeCompare(b.url)),
    ambiguous: ambiguous.sort((a, b) => a.url.localeCompare(b.url)),
  }, null, 2);
  const path = join(input.outputRoot, "auth_surface.json");
  await writeFile(path, body);
  return {
    probed: total,
    anonymous, authRequired, ambiguous, edgeBlocked,
    artifacts: [{ path, bytes: Buffer.byteLength(body) }],
  };
};

// ---------- IDOR prescreen ----------

export interface IdorInput {
  /** params_merged.json path. */
  readonly mergedFile: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxEndpoints?: number;
}

export interface IdorResult {
  readonly screened: number;
  readonly candidates: {
    url: string;
    param: string;
    original: string;
    variant: string;
    originalStatus: number;
    variantStatus: number;
    verdict: "same-response" | "different-response" | "not-found-on-variant";
  }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const ID_PARAM_RE = /(?:^|_)(?:id|uid|user_?id|uid|oid|cid|order_?id|oid|rid|pid|fid|aid|tid|sid)$/i;

export const prescreenIdor = async (input: IdorInput): Promise<IdorResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const endpoints = JSON.parse(await readFile(input.mergedFile, "utf8")) as {
    method: string; path: string; fields: { name: string; in: string }[];
  }[];
  const targets = endpoints
    .filter((e) => e.method === "GET")
    .map((e) => ({ e, idFields: e.fields.filter((f) => f.in === "query" && ID_PARAM_RE.test(f.name.replace(/\[\]$/, ""))) }))
    .filter((x) => x.idFields.length > 0)
    .slice(0, input.maxEndpoints ?? 15);

  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, cookie: input.cookie };
  const candidates: IdorResult["candidates"] = [];

  for (const { e, idFields } of targets) {
    for (const f of idFields.slice(0, 2)) {
      let base: URL;
      try { base = new URL(e.path); } catch { continue; } // one relative path must not crash the whole probe
      const name = f.name.replace(/\[\]$/, "");
      // Recorded query may carry the original value.
      const original = base.searchParams.get(name) ?? "1";
      base.searchParams.set(name, original);
      const orig = await fetchUrl(base.toString(), { ...opts, method: "GET" });
      if (orig.status === 0 || orig.status >= 400) continue;
      const origFp = `${orig.status}:${orig.sha256.slice(0, 16)}`;
      // Variant: numeric neighbor (cheap, deterministic).
      const shifted = String((Number(original) || 1) + 1);
      base.searchParams.set(name, shifted);
      const vari = await fetchUrl(base.toString(), { ...opts, method: "GET" });
      if (vari.status === 0) continue;
      const variFp = `${vari.status}:${vari.sha256.slice(0, 16)}`;
      candidates.push({
        url: base.toString(),
        param: name,
        original, variant: shifted,
        originalStatus: orig.status, variantStatus: vari.status,
        verdict: variFp === origFp ? "same-response" : vari.status === 404 ? "not-found-on-variant" : "different-response",
      });
    }
  }

  const path = join(input.outputRoot, "idor_prescreen.json");
  const body = JSON.stringify({ screened: targets.length, candidates }, null, 2);
  await writeFile(path, body);
  return { screened: targets.length, candidates, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
