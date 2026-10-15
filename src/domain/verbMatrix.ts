import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** HTTP verb/ACL matrix: cross GET/POST/PUT/DELETE/PATCH/OPTIONS against
 *  protected endpoints to find verb-level ACL gaps (GET blocked but PUT
 *  open, method-override tunnels, 405 vs 403 semantic drift). */

export interface VerbMatrixInput {
  readonly urls: string[];
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxUrls?: number;
  /** Fire DELETE/PUT/PATCH (mutating, potentially destructive). Default OFF:
   *  a verb probe that lands could modify or destroy real records. */
  readonly allowDestructive?: boolean;
}

export interface VerbMatrixResult {
  readonly probed: number;
  readonly matrix: { url: string; verb: string; status: number; bytes: number }[];
  /** endpoint × verb cells where an unauthenticated/low-priv caller gets 2xx on a mutating verb while GET is denied */
  readonly verbGaps: { url: string; verb: string; getBaseline: number; verbStatus: number; note: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const VERBS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] as const;
/** A mutating verb carrying a syntactically valid but empty body; never sent
 *  unless allowDestructive is set. */
const MUTATING_VERBS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

export const probeVerbMatrix = async (input: VerbMatrixInput): Promise<VerbMatrixResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, cookie: input.cookie, headers: input.headers };

  const urls = input.urls.slice(0, input.maxUrls ?? 15);
  const matrix: VerbMatrixResult["matrix"] = [];
  const verbGaps: VerbMatrixResult["verbGaps"] = [];

  const verbs = input.allowDestructive ? VERBS : VERBS.filter((v) => !MUTATING_VERBS.has(v));
  for (const url of urls) {
    let getBaseline = -1;
    for (const verb of verbs) {
      const r = await fetchUrl(url, { ...opts, method: verb, body: MUTATING_VERBS.has(verb) ? "{}" : undefined });
      matrix.push({ url, verb, status: r.status, bytes: r.bytes });
      if (verb === "GET") getBaseline = r.status;
      else if (getBaseline === 401 || getBaseline === 403) {
        // OPTIONS 200 is a CORS-preflight property, not an ACL gap — excluded.
        if (verb !== "OPTIONS" && r.status >= 200 && r.status < 300) {
          verbGaps.push({ url, verb, getBaseline, verbStatus: r.status, note: `${getBaseline} on GET but ${r.status} on ${verb} — verb-level ACL gap` });
        }
      }
    }
  }

  const body = JSON.stringify({ probed: urls.length, matrix, verbGaps }, null, 2);
  const path = join(input.outputRoot, "verb_matrix.json");
  await writeFile(path, body, "utf8");
  return { probed: urls.length, matrix, verbGaps, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
