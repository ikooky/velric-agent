import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Param differential probe: for each merged endpoint, remove one param at a
 * time and compare the response against the full-param baseline. Reveals
 * required params (4xx on removal) and params that change the response shape
 * (auth/feature switches) without any guessing. */

export interface ParamProbeInput {
  readonly mergedFile: string;
  readonly outputRoot: string;
  /** Origin for relative-path endpoints (paramMerge strips hosts). */
  readonly baseUrl?: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxEndpoints?: number;
}

export interface ParamProbeResult {
  readonly probed: number;
  readonly endpointResults: {
    method: string;
    url: string;
    baseline: { status: number; bytes: number; sha256: string };
    params: {
      name: string;
      removedStatus: number | null;
      delta: "same" | "status" | "body" | "error";
    }[];
  }[];
  readonly artifacts: { path: string; bytes: number }[];
  /** Endpoints skipped: relative path with no baseUrl provided. */
  readonly skippedRelativeEndpoints: number;
}

interface MergedEndpoint {
  method: string;
  path: string;
  fields: { name: string; in: string; samples?: number }[];
}

const parseExistingQuery = (url: string): URL => {
  try {
    return new URL(url);
  } catch {
    return new URL("http://placeholder.local");
  }
};

const fingerprint = (r: { status: number; bytes: number; sha256: string }) =>
  `${r.status}:${r.sha256.slice(0, 12)}:${r.bytes}`;

export const probeParams = async (input: ParamProbeInput): Promise<ParamProbeResult> => {
  const { readFile } = await import("node:fs/promises");
  const endpoints = JSON.parse(await readFile(input.mergedFile, "utf8")) as MergedEndpoint[];
  const cap = input.maxEndpoints ?? 10;
  const targets = endpoints.filter((e) => e.method === "GET" && e.fields.length > 0).slice(0, cap);

  const opts = { cookie: input.cookie, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };
  const endpointResults: ParamProbeResult["endpointResults"] = [];
  let skippedCount = 0;

  for (const ep of targets) {
    // Baseline: sample values from the recorded traffic are not stored per-field
    // in merged output; use "1" placeholders where absent — the DIFFERENTIAL is
    // what matters (same placeholder both sides), not absolute correctness.
    const buildUrl = (skip?: string): string => {
      const u = parseExistingQuery(ep.path);
      u.search = "";
      for (const f of ep.fields) {
        if (f.in !== "query" || f.name === skip) continue;
        // strip array brackets for a valid placeholder value
        u.searchParams.set(f.name.replace(/\[\]$/, ""), "1");
      }
      const abs = ep.path.startsWith("http") ? new URL(ep.path).origin : (input.baseUrl ?? "");
      if (!abs) { skippedCount++; return ""; } // relative path, no baseUrl — recorded, not silent
      return u.toString().replace("http://placeholder.local", abs);
    };
    const built = buildUrl();
    if (built === "") continue;
    const base = await fetchUrl(built, { ...opts });
    if (base.status === 0) continue; // endpoint unreachable — not probeable
    const baseline = { status: base.status, bytes: base.bytes, sha256: base.sha256 };
    const params: ParamProbeResult["endpointResults"][0]["params"] = [];
    for (const f of ep.fields.filter((x) => x.in === "query")) {
      const r = await fetchUrl(buildUrl(f.name), { ...opts });
      if (r.status === 0) {
        params.push({ name: f.name, removedStatus: null, delta: "error" });
        continue;
      }
      const delta =
        r.status !== baseline.status
          ? "status"
          : fingerprint(r) !== fingerprint(baseline)
            ? "body"
            : "same";
      params.push({ name: f.name, removedStatus: r.status, delta });
    }
    endpointResults.push({ method: ep.method, url: ep.path, baseline, params });
  }

  await mkdir(input.outputRoot, { recursive: true });
  const outPath = join(input.outputRoot, "param_probe.json");
  await writeFile(outPath, JSON.stringify({ probedAt: new Date().toISOString(), endpointResults }, null, 2));
  return {
    probed: endpointResults.length,
    endpointResults,
    artifacts: [{ path: outPath, bytes: Buffer.byteLength(JSON.stringify(endpointResults)) }],
    skippedRelativeEndpoints: skippedCount,
  };
};
