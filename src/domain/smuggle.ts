import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "undici";

/** HTTP request-smuggling differential probe: paired requests that differ in
 *  exactly ONE canonicalization dimension (path normalization, CL/TE framing,
 *  Host case). Parser divergence between edge and backend surfaces as
 *  differential status/time/body. Read-only shapes — no queue poisoning. */

export interface SmuggleInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface SmuggleResult {
  readonly baseUrl: string;
  readonly probed: number;
  readonly differentials: {
    dimension: string;
    variant: string;
    baselineStatus: number;
    variantStatus: number;
    baselineMs: number;
    variantMs: number;
    note: string;
  }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const VARIANT_GETS: { dimension: string; path: (base: string) => string }[] = [
  { dimension: "dot-segment", path: (b) => `${b}/x/../healthz-velric` },
  { dimension: "double-slash", path: (b) => `${b}//healthz-velric` },
  { dimension: "encoded-slash", path: (b) => `${b}/%2fhealthz-velric` },
  { dimension: "case", path: (b) => `${b}/HEALTHZ-VELRIC` },
  { dimension: "semicolon", path: (b) => `${b}/;/healthz-velric` },
  { dimension: "dotcase", path: (b) => `${b}/./healthz-velric` },
];

export const probeSmuggle = async (input: SmuggleInput): Promise<SmuggleResult> => {
  const base = input.baseUrl.replace(/\/$/, "");
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };
  const differentials: SmuggleResult["differentials"] = [];
  let probed = 0;

  // Baseline: the canonical random-ish path (almost certainly 404/soft-404).
  const basePath = `${base}/healthz-velric`;
  const baseline = await fetchUrl(basePath, opts);
  probed++;

  for (const v of VARIANT_GETS) {
    const r = await fetchUrl(v.path(base), opts);
    probed++;
    if (r.status === 0) continue;
    // Differential signal: a normalization variant answers differently from
    // the canonical path → two parsers disagree somewhere in the chain.
    if (r.status !== baseline.status) {
      differentials.push({
        dimension: v.dimension,
        variant: v.path(base).slice(base.length),
        baselineStatus: baseline.status,
        variantStatus: r.status,
        baselineMs: 0,
        variantMs: 0,
        note: "status divergence across normalization variants",
      });
    }
  }

  // CL+TE both present: raw client request — fetch APIs may strip the
  // conflicting pair before it reaches the wire.
  try {
    const client = new Client(base, { connect: { rejectUnauthorized: false } });
    const t0 = Date.now();
    const resP = client.request({
      path: "/healthz-velric",
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": "6",
        "transfer-encoding": "chunked",
      },
      body: "0\r\n\r\n",
    });
    const res = await Promise.race([
      resP.then(async (r) => {
        const { statusCode } = r;
        await r.body.dump?.().catch(() => {});
        return { status: statusCode, ms: Date.now() - t0 };
      }),
      new Promise<{ status: number; ms: number }>((resolve) => setTimeout(() => resolve({ status: -1, ms: Date.now() - t0 }), input.timeoutMs ?? 8000)),
    ]);
    probed++;
    // 400 from either parser = the pair was rejected (good). A clean
    // 200-family on CL+TE both = framing ambiguity.
    if (res.status >= 200 && res.status < 300) {
      differentials.push({ dimension: "CL+TE", variant: "both headers on POST", baselineStatus: baseline.status, variantStatus: res.status, baselineMs: 0, variantMs: res.ms, note: "both CL and TE accepted — framing ambiguity" });
    }
    await client.close().catch(() => {});
  } catch {
    /* raw client unavailable (e.g. via proxy) — skipped */
  }

  const result: SmuggleResult = { baseUrl: base, probed, differentials, artifacts: [] };
  const path = join(input.outputRoot, "smuggle_probe.json");
  const body = JSON.stringify(result, null, 2);
  await writeFile(path, body);
  result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
  return result;
};
