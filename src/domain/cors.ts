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
    verdict: "reflect" | "wildcard" | "null" | "none";
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

export const probeCors = async (input: CorsProbeInput): Promise<CorsProbeResult> => {
  const base = input.baseUrl.startsWith("http") ? input.baseUrl : `https://${input.baseUrl}`;
  await mkdir(input.outputRoot, { recursive: true });
  const origins = input.origins ?? [...DEFAULT_CORS_ORIGINS.slice(0, 1), suffixReflectionOrigin(base), ...DEFAULT_CORS_ORIGINS.slice(1)];

  const results: CorsProbeResult["results"] = [];
  for (const origin of origins) {
    const r = await fetchUrl(base, {
      ...input,
      headers: { Origin: origin },
      method: "OPTIONS",
      timeoutMs: input.timeoutMs ?? 10000,
    });
    const acao = r.headers["access-control-allow-origin"] ?? null;
    const acac = (r.headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true";
    let verdict: "reflect" | "wildcard" | "null" | "none" = "none";
    if (acao === "*") verdict = "wildcard";
    else if (acao === "null") verdict = "null";
    else if (acao && origin !== "null" && acao.includes(new URL(origin).hostname)) verdict = "reflect";
    else if (acao) verdict = "reflect";
    results.push({ origin, acao, acac, verdict });
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
