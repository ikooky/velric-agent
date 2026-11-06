/** Identity-preserving comparison helpers for authorization differentials.
 *
 * Normalization is deliberately opt-in for volatility: without repeated
 * same-context samples no field is assumed to be noise. Identity-bearing
 * fields are never masked by the learned profile.
 */
export interface NormalizationProfile { readonly volatilePaths: readonly string[] }

const VOLATILE_KEY = /^(?:ts|time|timestamp|timeStamp|serverTime|updatedAt|updatedAtIso|requestId|request_id|reqId|req_id|traceId|trace_id|traceIdStr|correlationId|correlation_id|xRequestId|nonce|csrfToken|csrf|xsrfToken)$/;
const IDENTITY_KEY = /(?:owner|object|tenant|user|account|identity|uuid|guid|principal|subject|session|token|^id$)/i;

const parse = (s: string): unknown => JSON.parse(s);
const escapePath = (key: string): string => key.replace(/~/g, "~0").replace(/\//g, "~1");
const leaves = (v: unknown, path = "", out = new Map<string, unknown>()): Map<string, unknown> => {
  if (v !== null && typeof v === "object") {
    if (Array.isArray(v)) {
      v.forEach((x, i) => leaves(x, `${path}/${i}`, out));
    } else {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) leaves(x, `${path}/${escapePath(k)}`, out);
    }
  } else out.set(path, v);
  return out;
};

const pathSegments = (path: string): string[] => path.split("/").slice(1).map((x) => x.replace(/~1/g, "/").replace(/~0/g, "~"));
const isIdentityPath = (path: string): boolean => pathSegments(path).some((segment) => IDENTITY_KEY.test(segment));
const opaqueIdentity = (value: unknown): boolean => typeof value === "string"
  && (/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value) || /^[\da-f]{16,}$/i.test(value));

export const learnNormalization = (samples: readonly string[]): NormalizationProfile => {
  if (samples.length < 2) return { volatilePaths: [] };
  try {
    const maps = samples.map((s) => leaves(parse(s)));
    const volatilePaths: string[] = [];
    for (const [path, value] of maps[0]!) {
      const key = pathSegments(path).at(-1) ?? "";
      if (!VOLATILE_KEY.test(key) || isIdentityPath(path) || maps.some((m) => opaqueIdentity(m.get(path)))) continue;
      if (maps.every((m) => m.has(path) && typeof m.get(path) === typeof value)
        && maps.some((m) => m.get(path) !== value)) volatilePaths.push(path);
    }
    return { volatilePaths };
  } catch {
    return { volatilePaths: [] };
  }
};

export const normalizeBody = (body: string, profile?: NormalizationProfile): string => {
  try {
    const masked = new Set(profile?.volatilePaths ?? []);
    const walk = (v: unknown, path: string): unknown => {
      // Default volatility: well-known volatile keys (timestamps, request ids,
      // nonces, csrf) are masked WITHOUT a learned profile — a single-sample
      // context still converges. Identity-bearing paths and opaque identity
      // values (uuid/long-hex) are never masked: owner data must survive.
      const key = pathSegments(path).at(-1) ?? "";
      const volatileByDefault = VOLATILE_KEY.test(key)
        && !isIdentityPath(path)
        && !(typeof v === "string" && v.length > 96);
      if (volatileByDefault || (masked.has(path) && !isIdentityPath(path) && !opaqueIdentity(v) && VOLATILE_KEY.test(key))) return "<volatile>";
      if (Array.isArray(v)) return v.map((x, i) => walk(x, `${path}/${i}`));
      if (v !== null && typeof v === "object") {
        return Object.fromEntries(Object.entries(v as Record<string, unknown>)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, x]) => [k, walk(x, `${path}/${escapePath(k)}`)]));
      }
      return v;
    };
    return JSON.stringify(walk(parse(body), ""));
  } catch {
    return body;
  }
};

interface TokenBag { map: Map<string, number>; count: number; truncated: boolean }
const tokens = (s: string, limit = 8000): TokenBag => {
  const map = new Map<string, number>();
  const all = s.match(/[\p{L}\p{N}_.-]+/gu) ?? [];
  const chosen = all.slice(0, limit);
  for (const token of chosen) map.set(token, (map.get(token) ?? 0) + 1);
  return { map, count: chosen.length, truncated: all.length > limit };
};

/** Multiset Jaccard. A capped comparison is intentionally never perfect: the
 * omitted suffix is unknown, not equal. */
export const tokenSimilarity = (a: string, b: string): number => {
  const ta = tokens(a), tb = tokens(b);
  if (ta.count === 0 || tb.count === 0) return 0;
  let intersection = 0, union = 0;
  for (const [token, count] of ta.map) {
    intersection += Math.min(count, tb.map.get(token) ?? 0);
    union += Math.max(count, tb.map.get(token) ?? 0);
  }
  for (const [token, count] of tb.map) if (!ta.map.has(token)) union += count;
  if (union === 0) return 0;
  const similarity = intersection / union;
  return ta.truncated || tb.truncated ? Math.min(similarity, 0.999999) : similarity;
};

/** Bounded character similarity. Exact LCS is used only for small inputs;
 * larger inputs use bounded n-gram overlap plus length agreement, avoiding a
 * synchronous O(n*m) event-loop stall and never claiming sampled equality. */
export const charSimilarity = (a: string, b: string): number => {
  if (!a.length || !b.length) return 0;
  if (a === b) return 1;
  const cells = a.length * b.length;
  if (cells > 250_000) {
    const grams = (s: string): Set<string> => {
      const out = new Set<string>();
      const step = Math.max(1, Math.ceil(s.length / 8000));
      for (let i = 0; i + 3 <= s.length; i += step) out.add(s.slice(i, i + 3));
      if (s.length >= 3) out.add(s.slice(-3));
      return out;
    };
    const x = grams(a), y = grams(b);
    if (!x.size || !y.size) return 0;
    let n = 0;
    for (const gram of x) if (y.has(gram)) n++;
    const overlap = (2 * n) / (x.size + y.size);
    const lengthAgreement = Math.min(a.length, b.length) / Math.max(a.length, b.length);
    return Math.min(0.999999, overlap * lengthAgreement);
  }
  let prev = new Uint32Array(b.length + 1);
  let cur = new Uint32Array(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    cur.fill(0);
    for (let j = 1; j <= b.length; j++) cur[j] = a[i - 1] === b[j - 1] ? prev[j - 1]! + 1 : Math.max(prev[j]!, cur[j - 1]!);
    [prev, cur] = [cur, prev];
  }
  return 2 * prev[b.length]! / (a.length + b.length);
};

