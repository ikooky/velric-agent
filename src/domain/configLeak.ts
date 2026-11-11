import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { charSimilarity, normalizeBody } from "./normalize.js";

/** Runtime config leakage in SPAs: config.js / env.js / runtime-config.json
 *  bundles that are served in production and carry keys the build-time
 *  "secrets don't ship" advice promised they wouldn't: Stripe, Firebase,
 *  Supabase service role, Mapbox, Sentry, Auth0, internal hosts, feature
 *  flags, staging URLs. Soft-404 calibrated so a SPA fallback page never
 *  counts as a config file. */

export interface ConfigLeakInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface ConfigFile {
  readonly path: string;
  readonly status: number;
  readonly bytes: number;
  readonly looksLikeConfig: boolean;
  readonly secretKinds: readonly string[];
  readonly evidence: string;
}

export interface ConfigLeakResult {
  readonly files: ConfigFile[];
  readonly secrets: { path: string; kind: string; masked: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const PATHS = [
  "/config.js", "/config.json", "/env.js", "/env.json", "/environment.js", "/runtime-config.json", "/runtime-config.js",
  "/app-config.js", "/app-config.json", "/settings.js", "/assets/config.json", "/assets/config.js", "/static/config.js",
  "/config/config.json", "/public/config.js", "/js/config.js", "/env-config.js", "/.env", "/.env.production", "/.env.local",
  "/config/env.js", "/src/config.js",
];

const SECRETS: { kind: string; re: RegExp }[] = [
  { kind: "stripe-pk", re: /pk_(?:live|test)_[A-Za-z0-9]{10,}/ },
  { kind: "stripe-sk", re: /sk_(?:live|test)_[A-Za-z0-9]{10,}/ },
  { kind: "google-api-key", re: /AIza[0-9A-Za-z_-]{30,}/ },
  { kind: "firebase-config", re: /"(?:apiKey|authDomain|projectId|storageBucket)"\s*:\s*"[^"]{4,}"/ },
  { kind: "supabase-key", re: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}/ },
  { kind: "mapbox-token", re: /pk\.[A-Za-z0-9_-]{40,}/ },
  { kind: "sentry-dsn", re: /https:\/\/[0-9a-f]{32}@[^"'\s]+\/\d+/ },
  { kind: "auth0-domain", re: /[a-z0-9-]+\.(?:eu\.|us\.)?auth0\.com/i },
  { kind: "aws-key", re: /AKIA[0-9A-Z]{16}/ },
  { kind: "generic-secret", re: /(?:API_KEY|apiKey|SECRET|secret|TOKEN|token|PASSWORD|password)["'\s]*[:=]\s*["'][^"']{8,}["']/ },
  { kind: "internal-host", re: /["'](?:https?:\/\/)?(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|localhost:\d+)[^"']*/ },
  { kind: "staging-url", re: /["']https?:\/\/[^"']*(?:staging|stage|preprod|uat|dev)[^"']*/i },
];

const mask = (s: string): string => (s.length <= 10 ? `${s.slice(0, 3)}***` : `${s.slice(0, 6)}***${s.slice(-3)} (${s.length})`);

export const probeConfigLeak = async (input: ConfigLeakInput): Promise<ConfigLeakResult> => {
  const base = new URL(input.baseUrl).href.replace(/\/$/, "");
  const soft = await fetchUrl(`${base}/velric-soft-${Date.now().toString(36)}.js`, { maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024 });
  const softNorm = normalizeBody(soft.body);
  const files: ConfigFile[] = [];
  const secrets: ConfigLeakResult["secrets"] = [];
  for (const p of PATHS) {
    const r = await fetchUrl(`${base}${p}`, { headers: input.cookie ? { cookie: input.cookie } : undefined, maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
    if (r.status >= 200 && r.status < 300) {
      const simSoft = soft.body ? charSimilarity(normalizeBody(r.body), softNorm) : 0;
      const isJsLike = /(json|javascript|text\/plain)/i.test(r.contentType) || /^[\s{([]/.test(r.body);
      const looksLikeConfig = isJsLike && simSoft < 0.95;
      if (!looksLikeConfig) { files.push({ path: p, status: r.status, bytes: r.bytes, looksLikeConfig, secretKinds: [], evidence: `SPA fallback (sim ${simSoft.toFixed(2)})` }); continue; }
      const kinds: string[] = [];
      for (const s of SECRETS) {
        const m = s.re.exec(r.body);
        if (!m) continue;
        kinds.push(s.kind);
        secrets.push({ path: p, kind: s.kind, masked: mask(m[1] ?? m[0]) });
      }
      files.push({ path: p, status: r.status, bytes: r.bytes, looksLikeConfig, secretKinds: kinds, evidence: kinds.length ? `${kinds.join(", ")}` : "config-shaped, no secret pattern" });
    } else if (r.status !== 404 && r.status !== 0) {
      files.push({ path: p, status: r.status, bytes: r.bytes, looksLikeConfig: false, secretKinds: [], evidence: `status ${r.status}` });
    }
  }
  const body = JSON.stringify({ base, files: files.filter((f) => f.looksLikeConfig || f.status !== 200), secrets }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "config_leak.json", body);
  return { files, secrets, artifacts: [artifact] };
};
