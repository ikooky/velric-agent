import { createHmac } from "node:crypto";
import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { fetchUrl } from "../adapters/http.js";

/** JWT analysis: decode payloads from harvested tokens (secret-scan bycatch),
 *  weak-HS256 dictionary crack, alg=none detection. All local except optional
 *  online-verification of a candidate secret. */

export interface JwtInspectInput {
  /** Secrets file (secrets.txt) OR jsDir to rescan, OR a raw token. */
  readonly secretsFile?: string;
  readonly jsDir?: string;
  readonly token?: string;
  readonly outputRoot: string;
  readonly wordlist?: string[];
  readonly proxy?: string;
}

export interface JwtInspectResult {
  readonly tokens: number;
  readonly analyses: {
    tokenPreview: string;
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    expired: boolean | null;
    algNone: boolean;
    weakSecret: string | null;
  }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const JWT_RE = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g;

const b64u = (s: string): Buffer => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

const WEAK_SECRETS = [
  "secret", "password", "123456", "1234567890", "qwerty", "abc123", "111111", "000000",
  "jwt_secret", "jwtsecret", "supersecret", "super-secret", "mysecret", "test", "dev",
  "key", "secretkey", "secret_key", "token", "changeme", "admin", "letmein", "welcome",
  "iloveyou", "monkey", "dragon", "master", "sunshine", "princess", "football",
  "hello", "freedom", "whatever", "qazwsx", "trustno1", "baseball", "shadow",
  "hnweb", "jwt", "sign", "signin", "auth", "sso", "passport", "session",
];

const crack = (token: string): string | null => {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) return null;
  const header = JSON.parse(b64u(h).toString("utf8")) as { alg?: string };
  if (!header.alg?.toUpperCase().startsWith("HS")) return null;
  const signingInput = `${h}.${p}`;
  for (const w of WEAK_SECRETS) {
    const sig = createHmac("sha256", w).update(signingInput).digest("base64url");
    if (sig === s) return w;
  }
  return null;
};

export const inspectJwt = async (input: JwtInspectInput): Promise<JwtInspectResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const tokens = new Set<string>();
  if (input.token) tokens.add(input.token.trim());

  const addFromText = (text: string): void => {
    for (const m of text.matchAll(JWT_RE)) tokens.add(m[0]);
  };
  if (input.secretsFile) {
    try { addFromText(await readFile(input.secretsFile, "utf8")); } catch { /* absent */ }
  }
  if (input.jsDir) {
    try {
      const files = (await readdir(input.jsDir)).filter((f) => f.endsWith(".js"));
      for (const f of files.slice(0, 300)) {
        try { addFromText(await readFile(join(input.jsDir, f), "utf8")); } catch { /* skip */ }
      }
    } catch { /* absent */ }
  }

  const analyses: JwtInspectResult["analyses"] = [];
  for (const t of [...tokens].slice(0, 50)) {
    const [h, p] = t.split(".");
    try {
      const header = JSON.parse(b64u(h!).toString("utf8")) as Record<string, unknown>;
      const payload = JSON.parse(b64u(p!).toString("utf8")) as Record<string, unknown>;
      const exp = typeof payload.exp === "number" ? payload.exp : null;
      const wordlist = input.wordlist ?? WEAK_SECRETS;
      const weakSecret = (() => {
        const [hh, pp, ss] = t.split(".");
        if (!hh || !pp || !ss) return null;
        const hd = JSON.parse(b64u(hh).toString("utf8")) as { alg?: string };
        if (!hd.alg?.toUpperCase().startsWith("HS")) return null;
        for (const w of wordlist) {
          if (createHmac("sha256", w).update(`${hh}.${pp}`).digest("base64url") === ss) return w;
        }
        return null;
      })();
      analyses.push({
        tokenPreview: `${t.slice(0, 24)}…${t.slice(-10)}`,
        header, payload,
        expired: exp !== null ? exp * 1000 < Date.now() : null,
        algNone: String(header.alg).toLowerCase() === "none",
        weakSecret,
      });
    } catch { /* malformed token — skip */ }
  }

  const path = join(input.outputRoot, "jwt_analysis.json");
  const body = JSON.stringify({ tokens: analyses.length, analyses }, null, 2);
  await writeFile(path, body);
  return { tokens: analyses.length, analyses, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
