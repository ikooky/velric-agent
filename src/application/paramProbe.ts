import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
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
    let relSkipped = false; // once per endpoint, not once per buildUrl call
    const buildUrl = (skip?: string): string => {
      // Relative paths must keep their path under the resolved base — the old
      // placeholder-replace lost the path segment entirely and probed the root.
      let u: URL;
      try {
        u = ep.path.startsWith("http") ? new URL(ep.path) : new URL(ep.path, input.baseUrl ?? "http://placeholder.local");
      } catch { skippedCount++; return ""; }
      u.search = "";
      for (const f of ep.fields) {
        if (f.in !== "query" || f.name === skip) continue;
        // strip array brackets for a valid placeholder value
        u.searchParams.set(f.name.replace(/\[\]$/, ""), "1");
      }
      if (ep.path.startsWith("http")) return u.toString(); // absolute: origin already correct
      if (!input.baseUrl) { relSkipped = true; return ""; } // relative path, no baseUrl — recorded, not silent
      try {
        const resolved = new URL(u.toString().replace("http://placeholder.local", new URL(input.baseUrl).origin));
        return resolved.toString();
      } catch { relSkipped = true; return ""; }
    };
    const built = buildUrl();
    if (built === "") { if (relSkipped) skippedCount++; continue; }
    const base = await fetchUrl(built, { ...opts });
    if (base.status === 0) continue; // endpoint unreachable — not probeable
    // Baseline stability calibration (same discipline as hiddenParams):
    // fetch the SAME url twice — a body-hash that moves between two
    // identical requests means per-request noise (timestamp/nonce), and
    // every remove-diff candidate would false-positive. Abort the whole
    // endpoint, never degrade to status-only for this probe family.
    const base2 = await fetchUrl(built, { ...opts });
    if (base2.status === 0) continue;
    const unstable = base2.status !== base.status || (base2.sha256 ?? "") !== (base.sha256 ?? "");
    if (unstable) {
      // Baseline noise: abort the whole endpoint. Recorded as an empty result
      // with baseline status -1 so downstream consumers see "not probed".
      endpointResults.push({ method: ep.method, url: ep.path, baseline: { status: -1, bytes: 0, sha256: "unstable-baseline" }, params: [] });
      continue;
    }
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

  const body = JSON.stringify({ probedAt: new Date().toISOString(), endpointResults }, null, 2);
  const art = await writeArtifact(input.outputRoot, "param_probe.json", body);
  return {
    probed: endpointResults.length,
    endpointResults,
    artifacts: [art],
    skippedRelativeEndpoints: skippedCount,
  };
};
