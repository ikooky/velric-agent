import { fetchUrl } from "../adapters/http.js";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { join } from "node:path";

/** Hidden-parameter miner (Param-Miner-style): guesses parameter NAMES the
 *  app never advertised, via paired-request differential — fire the request
 *  once with a candidate param and once without (both with a random cache
 *  buster so a CDN never serves a cached diff), flag any pair where the
 *  responses differ: the server READS that parameter.
 *
 *  Differences from probe_params: probe_params removes KNOWN params from
 *  merged recorded samples (which fields matter). This guesses UNKNOWN names
 *  from a wordlist + vocabulary learned from observed responses (learn
 *  observed words — the longer it runs the smarter the guesses).
 *
 *  Deterministic differential, no LLM. */

export interface HiddenParamInput {
  readonly url: string;
  readonly outputRoot: string;
  /** where to guess: query string, cookie names, or headers. Default query. */
  readonly in?: "query" | "cookie" | "header";
  /** Extra wordlist entries (merged over the built-in set). */
  readonly words?: readonly string[];
  /** Learn candidate words from response content (observed-words mode).
   *  Default true — extracts identifiers from baseline responses and probes
   *  them as parameter names too. */
  readonly learn?: boolean;
  readonly method?: string;
  readonly body?: string;
  readonly headers?: Record<string, string>;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxWords?: number;
  /** Bucket-bisection mode (param-miner): submit bucketSize candidate names
   *  per request; a response that differs from baseline halves the bucket and
   *  recurses — logarithmic requests for the same coverage. Default false
   *  (one-by-one with paired confirmation). */
  readonly bucketSize?: number;
}

export interface HiddenParamResult {
  readonly probed: number;
  readonly found: {
    readonly param: string;
    readonly in: "query" | "cookie" | "header";
    readonly evidence: string;
  }[];
  readonly artifacts: { path: string; bytes: number }[];
}

/** High-signal param wordlist (PortSwigger param-miner core subset — the
 *  words that actually find behavior differences in real apps). */
const BUILTIN_WORDS: readonly string[] = [
  // debug / feature switches
  "debug", "test", "dev", "stage", "internal", "admin", "debug_flag", "verbose", "trace", "log_level",
  "mock", "sandbox", "dry_run", "preview", "draft", "experimental", "beta", "alpha", "canary", "feature_flag",
  // auth / role overrides
  "role", "roles", "isAdmin", "is_admin", "admin", "as_user", "user_id", "userId", "account_id", "tenant",
  "tenant_id", "org_id", "organization_id", "impersonate", "sudo", "act_as", "on_behalf_of", "grant", "scope", "scopes",
  // routing overrides (cache poisoning classics)
  "url", "redirect", "redirect_uri", "redirect_url", "next", "return", "returnUrl", "return_to", "continue",
  "callback", "callbackUrl", "dest", "destination", "goto", "target", "rurl", "u",
  // header-injection params
  "x_forwarded_for", "x_forwarded_host", "x_original_url", "x_rewrite_url", "x_override_url", "real_ip",
  // file / path manipulation
  "file", "filename", "path", "filepath", "dir", "directory", "template", "page", "include", "require", "doc", "document",
  // query behavior
  "callback", "format", "output", "view", "theme", "lang", "locale", "currency", "region", "timezone",
  "sort", "order", "filter", "fields", "select", "limit", "offset", "page_size", "cursor", "since", "until",
  // upload/processing switches
  "process", "execute", "run", "eval", "exec", "render", "parse", "transform", "convert", "import", "export",
  // legacy / deprecated leftovers
  "old", "new", "v1", "v2", "version", "api_version", "legacy", "compat", "fallback", "backup", "copy",
  // OAuth/token surfaces
  "access_token", "refresh_token", "id_token", "code", "state", "nonce", "client_id", "client_secret", "api_key", "apikey",
];

const CACHE_BUSTER = "fcbz";

/** Extract learnable candidate words from response bodies: camelCase/snake
 *  identifiers of 3-24 chars that look like field names. */
const learnWords = (bodies: readonly string[], cap = 200): string[] => {
  const out = new Set<string>();
  for (const b of bodies) {
    const re = /\b(?:[a-z][a-zA-Z0-9]{2,23}|[a-z]+_[a-z0-9_]{2,23})\b/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(b)) !== null && out.size < cap) {
      const w = m[0];
      if (!/^(?:the|and|for|you|this|that|with|from|have|not|are|was|but|his|her|its|our|their|has|had|will|would|could|should)$/.test(w)) out.add(w);
    }
  }
  return [...out];
};

const fp = (r: { status: number; bytes: number; sha256: string }): string => `${r.status}:${r.sha256.slice(0, 12)}:${r.bytes}`;

export const mineHiddenParams = async (input: HiddenParamInput): Promise<HiddenParamResult> => {
  await ensureDir(input.outputRoot);
  const where = input.in ?? "query";
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, method: input.method ?? "GET", body: input.body, headers: input.headers, cookie: input.cookie };

  // --- calibration: a few baseline rounds to learn the noise floor.
  // Flaky endpoints (rotating tokens/timestamps in body) would diff on EVERY
  // param; require TWO consecutive identical baselines before trusting diffs.
  const baselineRound = async (): Promise<{ fp: string; body: string }> => {
    const u = new URL(input.url);
    u.searchParams.set(CACHE_BUSTER, String(Math.random()).slice(2, 10));
    const r = await fetchUrl(u.toString(), opts);
    return { fp: fp(r), body: r.body };
  };
  const b1 = await baselineRound();
  const b2 = await baselineRound();
  const stable = b1.fp === b2.fp;
  if (!stable) {
    const bodyStr = JSON.stringify({ probed: 0, found: [], note: "baseline unstable (rotating content) — differential not trustworthy, aborted" }, null, 2);
    const art = await writeArtifact(input.outputRoot, "hidden_params.json", bodyStr);
    return { probed:0, found: [], artifacts: [art] };
  }

  // --- candidate words: builtin + caller + learned vocabulary.
  const words = [...new Set([...BUILTIN_WORDS, ...(input.words ?? [])])];
  const learned = (input.learn ?? true) ? learnWords([b1.body, b2.body]) : [];
  const candidates = [...new Set([...words, ...learned])]
    .filter((w) => w !== CACHE_BUSTER)
    .slice(0, input.maxWords ?? 300);

  const found: HiddenParamResult["found"] = [];
  let probed = 0;

  if (input.bucketSize !== undefined && input.bucketSize > 1 && where === "query") {
    // ---- bucket bisection (param-miner guessParams) ----
    // One request carries `bucketSize` candidate names at once. A response
    // that differs from the stable baseline means SOME name in the bucket is
    // read → split and recurse. Converges to single names in log2 requests.
    const inject = (names: string[]): string => {
      const u = new URL(input.url);
      u.searchParams.set(CACHE_BUSTER, String(Math.random()).slice(2, 10));
      for (const n of names) u.searchParams.set(n, "1");
      return u.toString();
    };
    const differs = async (names: string[]): Promise<boolean> => {
      const r = await fetchUrl(inject(names), opts);
      probed++;
      if (r.status === 0) return false;
      return fp(r) !== b1.fp;
    };
    const permute = (w: string): string => w.split("").sort().reverse().join("");
    const queue: string[][] = [];
    for (let i = 0; i < candidates.length; i += input.bucketSize) queue.push(candidates.slice(i, i + input.bucketSize));
    while (queue.length > 0) {
      const bucket = queue.shift()!;
      if (bucket.length === 0) continue;
      if (!(await differs(bucket))) continue; // whole bucket dead — one request cleared N names
      if (bucket.length === 1) {
        const w = bucket[0]!;
        // negative control (param-miner permute): the letter-shuffled junk name
        // must NOT reproduce the diff, else the endpoint reacts to ANY extra
        // input and every candidate would false-positive.
        const junk = permute(w);
        if (junk !== w && (await differs([junk]))) continue;
        const ev = await differs([w]);
        found.push({ param: w, in: where, evidence: `bucket-bisect: response differs with param, junk-anagram does not (status ${b1.fp.split(":")[0]} base)` });
        if (!ev) break;
        continue;
      }
      const mid = Math.floor(bucket.length / 2);
      queue.push(bucket.slice(0, mid), bucket.slice(mid));
    }
    const bodyStr = JSON.stringify({ probed, found, where, learnedWords: learned.length, mode: "bucket-bisect" }, null, 2);
    const art = await writeArtifact(input.outputRoot, "hidden_params.json", bodyStr);
    return { probed, found, artifacts: [art] };
  }

  for (const w of candidates) {
    // paired probe with distinct cache busters on BOTH sides
    const mk = (withParam: boolean): string => {
      const u = new URL(input.url);
      u.searchParams.set(CACHE_BUSTER, String(Math.random()).slice(2, 10));
      if (withParam) {
        if (where === "query") u.searchParams.set(w, "1");
      }
      return u.toString();
    };
    const hdr = (withParam: boolean): Record<string, string> => {
      if (!withParam) return {};
      if (where === "header") return { [w]: "1" };
      if (where === "cookie") return { cookie: `${input.cookie ? input.cookie + "; " : ""}${w}=1` };
      return {};
    };
    // with-param request (cookie/header modes also ride the query buster)
    const withR = where === "query"
      ? await fetchUrl(mk(true), opts)
      : await fetchUrl(mk(false), { ...opts, headers: { ...(input.headers ?? {}), ...hdr(true) }, cookie: where === "cookie" ? undefined : input.cookie });
    probed++;
    const withoutR = where === "query"
      ? await fetchUrl(mk(false), opts)
      : await fetchUrl(mk(false), { ...opts, headers: input.headers, cookie: input.cookie });
    if (withR.status === 0 || withoutR.status === 0) continue;
    if (fp(withR) === fp(withoutR)) continue;
    // responses differ — the param is READ. Second confirmation round to kill
    // one-off flakiness the double-baseline didn't catch.
    const confirm = where === "query"
      ? await fetchUrl(mk(true), opts)
      : await fetchUrl(mk(false), { ...opts, headers: { ...(input.headers ?? {}), ...hdr(true) }, cookie: where === "cookie" ? undefined : input.cookie });
    const confirmBase = where === "query"
      ? await fetchUrl(mk(false), opts)
      : await fetchUrl(mk(false), { ...opts, headers: input.headers, cookie: input.cookie });
    if (fp(confirm) === fp(confirmBase)) continue; // flake — diff didn't reproduce
    found.push({ param: w, in: where, evidence: `status ${withoutR.status}->${withR.status}, ${withoutR.bytes}B->${withR.bytes}B (confirmed twice)` });
  }

  const bodyStr = JSON.stringify({ probed, found, where, learnedWords: learned.length }, null, 2);
  const art = await writeArtifact(input.outputRoot, "hidden_params.json", bodyStr);
  return { probed, found, artifacts: [art] };
};
