import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import net from "node:net";
import tls from "node:tls";

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

  // CL+TE both present — BYTE-LEVEL raw socket. HTTP client libraries
  // (undici, node fetch, node:http) all re-frame the body and undici
  // rejects the conflicting pair outright ("invalid transfer-encoding
  // header") before anything reaches the wire; only a hand-written
  // request guarantees the exact CL+TE bytes arrive at the server.
  try {
    const u = new URL(base);
    const port = Number(u.port || (u.protocol === "https:" ? 443 : 80));
    const t0 = Date.now();
    // Host must carry the port when non-default (HTTP/1.1 virtual hosts and
    // some proxies route on it); body `0\r\n\r\n` is exactly 5 bytes — CL
    // must match the wire truth byte-for-byte or the probe itself desyncs.
    const hostHeader = u.port ? `${u.hostname}:${u.port}` : u.hostname;
    const raw = `POST /healthz-velric HTTP/1.1\r\nHost: ${hostHeader}\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n`;
    const res = await new Promise<{ status: number; ms: number }>((resolve) => {
      const sock: net.Socket = u.protocol === "https:"
        ? tls.connect({ host: u.hostname, port, rejectUnauthorized: false, servername: u.hostname })
        : net.connect({ host: u.hostname, port });
      let head = "";
      const finish = (status: number): void => { sock.destroy(); resolve({ status, ms: Date.now() - t0 }); };
      const timer = setTimeout(() => finish(-1), input.timeoutMs ?? 8000);
      sock.on("error", () => { clearTimeout(timer); finish(0); });
      sock.on("connect", () => { sock.write(raw); });
      sock.on("data", (d: Buffer) => {
        head += d.toString("latin1");
        const m = head.match(/^HTTP\/[\d.]+\s+(\d{3})/);
        if (m) { clearTimeout(timer); finish(Number(m[1])); } // status line is all we need
      });
      sock.on("close", () => { clearTimeout(timer); if (!/^HTTP\//.test(head)) finish(0); });
    });
    probed++;
    // 400 from either parser = the pair was rejected (good). A clean
    // 200-family on CL+TE both = framing ambiguity.
    if (res.status >= 200 && res.status < 300) {
      differentials.push({ dimension: "CL+TE", variant: "both headers on POST", baselineStatus: baseline.status, variantStatus: res.status, baselineMs: 0, variantMs: res.ms, note: "both CL and TE accepted — framing ambiguity" });
    }
  } catch {
    /* raw socket unavailable (e.g. via SOCKS proxy) — skipped */
  }

  const result: SmuggleResult = { baseUrl: base, probed, differentials, artifacts: [] };
  const path = join(input.outputRoot, "smuggle_probe.json");
  const body = JSON.stringify(result, null, 2);
  await writeFile(path, body);
  result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
  return result;
};
