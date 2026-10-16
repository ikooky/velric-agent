import { rawHttpExchange, type RawHttpResult } from "../adapters/rawTunnel.js";
import { writeArtifact } from "../adapters/artifacts.js";

export interface SmuggleInput {
  readonly baseUrl: string; readonly outputRoot: string; readonly proxy?: string; readonly timeoutMs?: number;
  readonly signal?: AbortSignal; readonly rejectUnauthorized?: boolean;
}
interface Attempt { dimension: string; path: string; status: number; complete: boolean; requestHash: string; responseHash: string; elapsedMs: number; error?: string; receiptId?: string }
export interface SmuggleResult {
  readonly baseUrl: string; readonly probed: number; readonly confirmed: false;
  readonly attempts: Attempt[];
  readonly differentials: { dimension: string; variant: string; baselineStatus: number; variantStatus: number; baselineMs: number; variantMs: number; note: string; outcome: "candidate" }[];
  readonly artifacts: { path: string; bytes: number }[];
}
/** Canonicalization and framing acceptance are candidates, not proof of desync. */
export const probeSmuggle = async (input: SmuggleInput): Promise<SmuggleResult> => {
  const u = new URL(input.baseUrl); if (!["http:", "https:"].includes(u.protocol)) throw new Error("unsupported URL protocol");
  const prefix = u.pathname.replace(/\/$/, ""); const canonical = `${prefix}/healthz-velric`;
  const variants = [
    ["dot-segment", `${prefix}/x/../healthz-velric`], ["double-slash", `${prefix}//healthz-velric`],
    ["encoded-slash", `${prefix}/%2fhealthz-velric`], ["case", `${prefix}/HEALTHZ-VELRIC`],
    ["semicolon", `${prefix}/;/healthz-velric`], ["dotcase", `${prefix}/./healthz-velric`],
  ] as const;
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, signal: input.signal, rejectUnauthorized: input.rejectUnauthorized, maxBytes: 262144 };
  const attempts: Attempt[] = []; const differentials: SmuggleResult["differentials"] = [];
  const run = async (dimension: string, path: string, framing = false): Promise<RawHttpResult> => {
    const raw = framing
      ? `POST ${path} HTTP/1.1\r\nHost: ${u.host}\r\nConnection: close\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n`
      : `GET ${path} HTTP/1.1\r\nHost: ${u.host}\r\nConnection: close\r\n\r\n`;
    const r = await rawHttpExchange(u.origin + path, Buffer.from(raw, "latin1"), opts);
    attempts.push({ dimension, path, status: r.status, complete: r.complete, requestHash: r.requestHash, responseHash: r.responseHash, elapsedMs: r.elapsedMs, ...(r.error ? { error: r.error } : {}), ...(r.receiptId ? { receiptId: r.receiptId } : {}) });
    return r;
  };
  const baseline = await run("baseline", canonical);
  if (baseline.complete && baseline.status > 0) for (const [dimension, path] of variants) {
    if (input.signal?.aborted) break;
    const r = await run(dimension, path);
    if (r.complete && r.status > 0 && (r.status !== baseline.status || r.responseHash !== baseline.responseHash)) differentials.push({ dimension, variant: path, baselineStatus: baseline.status, variantStatus: r.status, baselineMs: baseline.elapsedMs, variantMs: r.elapsedMs, outcome: "candidate", note: "single-hop response difference; parser disagreement and request desynchronization unproven" });
  }
  if (!input.signal?.aborted) {
    const r = await run("CL+TE", canonical, true);
    if (r.complete && r.status >= 200 && r.status < 300) differentials.push({ dimension: "CL+TE", variant: canonical, baselineStatus: baseline.status, variantStatus: r.status, baselineMs: baseline.elapsedMs, variantMs: r.elapsedMs, outcome: "candidate", note: "conflicting framing accepted; no second-parser disagreement or desync demonstrated" });
  }
  const result: SmuggleResult = { baseUrl: input.baseUrl, probed: attempts.length, confirmed: false, attempts, differentials, artifacts: [] };
  return { ...result, artifacts: [await writeArtifact(input.outputRoot, "smuggle_probe.json", JSON.stringify(result, null, 2))] };
};
