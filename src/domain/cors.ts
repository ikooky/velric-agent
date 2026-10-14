import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** CORS misconfiguration probe: Origin variants (evil / reflected / null),
 *  deterministic ACAO/ACAC combination detection. */

export interface CorsProbeInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly origins?: string[];
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface CorsProbeResult {
  readonly baseUrl: string;
  readonly results: {
    origin: string;
    acao: string | null;
    acac: boolean;
    verdict: "reflect" | "wildcard" | "null" | "static" | "none";
  }[];
  readonly misconfigured: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

export const DEFAULT_CORS_ORIGINS: readonly string[] = [
  "https://evil-velric.example.com",
  "null",
  "http://localhost:8080",
];

/** Suffix-reflection variant built from the target host:
 *  https://<target-host>.evil-velric.example.com — catches sloppy
 *  suffix-matching ACAO allowlists. */
const suffixReflectionOrigin = (baseUrl: string): string => {
  try {
    return `https://${new URL(baseUrl).hostname}.evil-velric.example.com`;
  } catch {
    return "https://suffix.evil-velric.example.com";
  }
};

/** ACAO reflection must match the probe origin's HOST (parsed, not substring
 *  contains): "https://evil-velric.example.com" must not classify as a
 *  reflection of "https://velric.example.com". */
const sameHost = (acao: string, origin: string): boolean => {
  try {
    const a = new URL(acao);
    const o = new URL(origin);
    return a.protocol === o.protocol && a.hostname === o.hostname && (a.port === o.port || (a.port === "" && o.port === ""));
  } catch {
    return acao === origin;
  }
};

export const probeCors = async (input: CorsProbeInput): Promise<CorsProbeResult> => {
  const base = input.baseUrl.startsWith("http") ? input.baseUrl : `https://${input.baseUrl}`;
  await mkdir(input.outputRoot, { recursive: true });
  const origins = input.origins ?? [...DEFAULT_CORS_ORIGINS.slice(0, 1), suffixReflectionOrigin(base), ...DEFAULT_CORS_ORIGINS.slice(1)];

  const results: CorsProbeResult["results"] = [];
  for (const origin of origins) {
    // Preflight AND actual-request probes: some servers reflect ACAO+ACAC
    // only on simple GET responses — an OPTIONS-only probe reports them as
    // safe (false-safe). Merge: the worse verdict of the two wins.
    const probe = async (method: "OPTIONS" | "GET"): Promise<{ acao: string | null; acac: boolean }> => {
      const r = await fetchUrl(base, {
        ...input,
        headers: { Origin: origin },
        method,
        timeoutMs: input.timeoutMs ?? 10000,
      });
      return {
        acao: r.headers["access-control-allow-origin"] ?? null,
        acac: (r.headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true",
      };
    };
    // Each method's response is judged AS A PAIR — merging ACAO from one
    // response with ACAC from another fabricates a combination the server
    // never emitted. The worse PER-RESPONSE verdict wins.
    const judge = (acao: string | null, acac: boolean): "reflect" | "wildcard" | "null" | "static" | "none" => {
      if (acao === "*") return "wildcard";
      if (acao === "null") return "null";
      if (acao && origin !== "null" && sameHost(acao, origin)) return "reflect";
      if (acao) return "static";
      return "none";
    };
    const rank = { none: 0, static: 1, wildcard: 2, null: 3, reflect: 4 } as const;
    const pre = await probe("OPTIONS");
    const act = await probe("GET");
    const preV = judge(pre.acao, pre.acac);
    const actV = judge(act.acao, act.acac);
    const usePre = rank[preV] >= rank[actV];
    const acao = usePre ? pre.acao : act.acao;
    const acac = usePre ? pre.acac : act.acac;
    results.push({ origin, acao, acac, verdict: usePre ? preV : actV });
  }

  const misconfigured = results.some((r) =>
    (r.verdict === "reflect" && r.acac) ||
    (r.verdict === "null" && r.acac),
  );
  const path = join(input.outputRoot, "cors_probe.json");
  const body = JSON.stringify({ baseUrl: base, results, misconfigured }, null, 2);
  await writeFile(path, body);
  return { baseUrl: base, results, misconfigured, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
