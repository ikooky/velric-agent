/**
 * Parameter-diff / merge logic: read multiple recorded samples of the same
 * endpoint and produce merged field sets with confidence, per api-recon J7.
 */

export interface ParamSample {
  readonly method: string;
  readonly url: string;
  readonly action?: string;
  readonly body?: string | null;
  readonly query?: string | null;
}

export interface MergedParam {
  readonly name: string;
  readonly in: "body" | "query";
  readonly samples: number;
  readonly confidence: "high" | "medium" | "low" | "pending";
}

export interface MergedEndpoint {
  readonly method: string;
  readonly path: string;
  readonly fields: MergedParam[];
}

const pathOf = (url: string): string => url.split("?")[0] ?? url;

const collectKeys = (
  raw: string | null | undefined,
  into: Map<string, Set<number>>,
  sampleIdx: number,
): void => {
  if (!raw) return;
  const text = raw.trim();
  if (text.startsWith("{") || text.startsWith("[")) {
    try {
      const parsed = JSON.parse(text) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        for (const k of Object.keys(parsed)) {
          (into.get(k) ?? into.set(k, new Set()).get(k)!).add(sampleIdx);
        }
      }
      return;
    } catch {
      /* fall through to form-encoding */
    }
  }
  for (const pair of text.split("&")) {
    const k = pair.split("=")[0];
    if (k) (into.get(k) ?? into.set(k, new Set()).get(k)!).add(sampleIdx);
  }
};

const confidenceFor = (hits: number, samples: number): MergedParam["confidence"] => {
  if (samples >= 2 && hits >= 2) return "high";
  if (hits >= 1) return "medium";
  return "pending";
};

/**
 * Merge parameter samples grouped by endpoint. A field seen in every sample is
 * high confidence; a field seen once is medium; the count is always reported so
 * a single sample never silently implies required/optional.
 */
export const mergeParams = (samples: readonly ParamSample[]): MergedEndpoint[] => {
  interface Agg {
    method: string;
    path: string;
    body: Map<string, Set<number>>;
    query: Map<string, Set<number>>;
    seen: number;
  }
  const byEndpoint = new Map<string, Agg>();
  samples.forEach((s, idx) => {
    // Be tolerant of partial captures: a sample without method+url carries no
    // endpoint identity — skip it instead of crashing on undefined.
    if (!s || typeof s.url !== "string" || !s.url || !s.method) return;
    const path = pathOf(s.url);
    const key = `${s.method.toUpperCase()} ${path}`;
    const agg =
      byEndpoint.get(key) ??
      byEndpoint
        .set(key, {
          method: s.method.toUpperCase(),
          path,
          body: new Map(),
          query: new Map(),
          seen: 0,
        })
        .get(key)!;
    agg.seen += 1;
    collectKeys(s.body, agg.body, idx);
    const q = s.query ?? (s.url.includes("?") ? s.url.split("?")[1] : null);
    collectKeys(q, agg.query, idx);
  });

  const out: MergedEndpoint[] = [];
  for (const agg of byEndpoint.values()) {
    const fields: MergedParam[] = [];
    for (const [where, m] of [
      ["body", agg.body],
      ["query", agg.query],
    ] as const) {
      for (const [name, hits] of m) {
        fields.push({
          name,
          in: where,
          samples: hits.size,
          confidence: confidenceFor(hits.size, agg.seen),
        });
      }
    }
    fields.sort((a, b) => a.name.localeCompare(b.name));
    out.push({ method: agg.method, path: agg.path, fields });
  }
  out.sort((a, b) => `${a.path}`.localeCompare(`${b.path}`));
  return out;
};