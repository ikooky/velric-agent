/**
 * Volatile-content normalization for differential verdicts (Authz-ExeC
 * EnforcementDetector discipline): before hashing/comparing two response
 * bodies, rewrite volatile token classes to fixed placeholders so that
 * per-request noise (timestamps, request-ids, nonces, CSRF values, HTML
 * comments) cannot make "same content" look "different".
 *
 * Every pattern here is deterministic; the module is pure. Applied on BOTH
 * sides of every body comparison (recorded blob fingerprints and live replay
 * fingerprints) — normalizing only one side makes diffs strictly worse.
 */

const RULES: readonly { readonly re: RegExp; readonly sub: string }[] = [
  // UUIDs (v4-ish, any variant nibble)
  { re: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, sub: "<uuid>" },
  // ISO-8601 timestamps (with/without ms, Z or offset)
  { re: /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?\b/g, sub: "<iso-ts>" },
  // Chinese-style dates 2026年10月16日 / 2026/10/16 / 2026-10-16
  { re: /\b\d{4}[-/年]\d{1,2}[-/月]\d{1,2}日?\b/g, sub: "<date>" },
  // Unix epoch seconds (10) / millis (13)
  { re: /\b1[0-9]{9}\b/g, sub: "<unix-s>" },
  { re: /\b1[0-9]{12}\b/g, sub: "<unix-ms>" },
  // CSRF / nonce / viewstate / anti-forgery values
  { re: /(csrf[^"'=]{0,20}|nonce[^"'=]{0,20}|viewstate[^"'=]{0,20}|antiforgery[^"'=]{0,20}|synchronizer[^"'=]{0,20})["'=:\s]+[A-Za-z0-9+/_=-]{16,}/gi, sub: "$1<token>" },
  // request-id / trace-id / correlation-id header-ish values — key-adjacent
  // random strings of ANY length (JSON values are quote-delimited, so match
  // inside quotes or after = : separators)
  { re: /((?:request|trace|correlation|x-request|req)[-_]?id"?)[:=]\s*"?[A-Za-z0-9-]{6,}"?/gi, sub: "$1:<reqid>" },
  // camelCase variants: reqId/traceId/requestId/correlationId
  { re: /((?:request|trace|correlation|req)Id"?)[:=]\s*"?[A-Za-z0-9-]{6,}"?/g, sub: "$1:<reqid>" },
  // bare short random hex/alnum ids (16+ chars) used as opaque identifiers
  { re: /\b[0-9a-f]{12,}\b/gi, sub: "<hexid>" },
  // opaque 32+ hex (hash digests) and 20+ base64url (opaque tokens)
  { re: /\b[0-9a-f]{32,}\b/gi, sub: "<hash>" },
  { re: /["'](?=[A-Za-z0-9_-]{24,})(?=[^"']*\d)(?=[^"']*[A-Z])(?=[^"']*[a-z])[A-Za-z0-9_-]{24,}={0,2}["']/g, sub: '"<b64>"' },
  // HTML comments (build banners, timestamps in comment markers)
  { re: /<!--[\s\S]*?-->/g, sub: "<!--comment-->" },
  // whitespace folding + lowercase for stable ordering
];

/** Normalize a response body for comparison. Cheap single pass; safe on any text. */
export const normalizeBody = (body: string): string => {
  let out = body;
  for (const { re, sub } of RULES) out = out.replace(re, sub);
  return out.toLowerCase().replace(/\s+/g, " ");
};

/**
 * Token-overlap similarity (0..1) for the SIMILAR tier: weighted Jaccard over
 * normalized token multisets, capacity-capped (Authz-ExeC similarity()). Used
 * when normalized hashes differ — content may still be effectively the same.
 */
export const tokenSimilarity = (a: string, b: string): number => {
  const CAP = 8000; // token capacity — same clamp as Authz-ExeC
  const toks = (s: string): Map<string, number> => {
    const m = new Map<string, number>();
    for (const t of s.split(/[^a-z0-9<>.-]+/).slice(0, CAP)) {
      if (t.length < 2) continue;
      m.set(t, (m.get(t) ?? 0) + 1);
    }
    return m;
  };
  const ma = toks(a);
  const mb = toks(b);
  if (ma.size === 0 && mb.size === 0) return 1;
  let inter = 0;
  let union = 0;
  for (const [t, c] of ma) {
    const d = mb.get(t) ?? 0;
    inter += Math.min(c, d);
    union += Math.max(c, d);
  }
  for (const [t, d] of mb) if (!ma.has(t)) union += d;
  return union === 0 ? 1 : inter / union;
};

/** Structural (schema) similarity for JSON bodies: key-set Jaccard, ignoring
 *  values — detects "same object type, different owner" (rescoped candidates). */
export const schemaSimilarity = (a: string, b: string): number => {
  const keys = (s: string): Set<string> => {
    const out = new Set<string>();
    try {
      const walk = (o: unknown, prefix: string): void => {
        if (o && typeof o === "object") {
          for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
            out.add(`${prefix}.${k}`);
            walk(v, `${prefix}.${k}`);
          }
        }
      };
      walk(JSON.parse(s), "");
    } catch { /* non-JSON → empty keyset, similarity degrades */ }
    return out;
  };
  const ka = keys(a);
  const kb = keys(b);
  if (ka.size === 0 && kb.size === 0) return tokenSimilarity(a, b);
  let inter = 0;
  for (const k of ka) if (kb.has(k)) inter++;
  return (ka.size + kb.size - inter) === 0 ? 1 : inter / (ka.size + kb.size - inter);
};
