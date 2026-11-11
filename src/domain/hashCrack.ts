import { createHash, scryptSync, pbkdf2Sync, timingSafeEqual } from "node:crypto";

/** Offline hash cracking for loot from dumps: identify the algorithm, then
 *  dictionary + rule mutation attack (case, suffix digits, years, leet).
 *  Supports raw digests (md5/sha1/sha256/sha512/sha3) plus scrypt and
 *  pbkdf2 (Django style). bcrypt is identified but not computed in-process. */

export interface CrackInput {
  readonly hashes: readonly string[];
  readonly outputRoot: string;
  readonly wordlist?: readonly string[];
  /** Extra rules on top of the built-in set (none default off). */
  readonly rules?: boolean;
  readonly maxSeconds?: number;
}

export interface Cracked {
  readonly hash: string;
  readonly algorithm: string;
  readonly plaintext: string;
  readonly rule: string;
  readonly attempts: number;
}

export interface CrackResult {
  readonly cracked: Cracked[];
  readonly unsupported: { hash: string; algorithm: string; note: string }[];
  readonly attempts: number;
  readonly elapsedMs: number;
  readonly artifacts: { path: string; bytes: number }[];
}

const WORDS = [
  "password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein", "dragon", "111111", "baseball",
  "iloveyou", "trustno1", "sunshine", "master", "welcome", "shadow", "ashley", "football", "jesus", "michael",
  "ninja", "mustang", "password1", "admin", "administrator", "root", "toor", "guest", "test", "demo",
  "changeme", "secret", "passw0rd", "p@ssw0rd", "qwerty123", "1q2w3e4r", "zaq12wsx", "starwars", "superman", "batman",
  "summer", "winter", "spring", "autumn", "january", "december", "company", "corp", "office", "server",
  "oracle", "mysql", "postgres", "redis", "docker", "kubernetes", "jenkins", "gitlab", "grafana", "nacos",
  "michael1", "jessica", "charlie", "donald", "daniel", "andrew", "joshua", "matthew", "hunter", "ranger",
];

const BASE_RULES: { name: string; apply: (w: string) => string }[] = [
  { name: "identity", apply: (w) => w },
  { name: "upper-first", apply: (w) => w.charAt(0).toUpperCase() + w.slice(1) },
  { name: "upper", apply: (w) => w.toUpperCase() },
  { name: "leet", apply: (w) => w.replace(/a/g, "@").replace(/o/g, "0").replace(/e/g, "3").replace(/i/g, "1").replace(/s/g, "$") },
];
const SUFFIXES = ["", "0", "1", "2", "7", "9", "00", "01", "11", "12", "21", "69", "99", "123", "1234", "12345", "!", "@", "#", "2021", "2022", "2023", "2024", "2025", "2026"];

/** Candidates: base mutation × suffix. Verify-based algorithms (pbkdf2/
 *  scrypt, 100k+ iterations) drop the suffix axis to stay in budget. */
const candidates = (word: string, combos: boolean): { cand: string; rule: string }[] => {
  const out: { cand: string; rule: string }[] = [];
  for (const b of BASE_RULES) {
    const base = b.apply(word);
    if (!combos) { out.push({ cand: base, rule: b.name }); continue; }
    for (const suf of SUFFIXES) out.push({ cand: `${base}${suf}`, rule: suf ? `${b.name}+suffix-${suf}` : b.name });
  }
  return out;
};

const ALGOS: { name: string; re: RegExp; digest?: (s: string, salt?: string) => string }[] = [
  { name: "md5", re: /^[a-f0-9]{32}$/i, digest: (s) => createHash("md5").update(s).digest("hex") },
  { name: "sha1", re: /^[a-f0-9]{40}$/i, digest: (s) => createHash("sha1").update(s).digest("hex") },
  { name: "sha256", re: /^[a-f0-9]{64}$/i, digest: (s) => createHash("sha256").update(s).digest("hex") },
  { name: "sha512", re: /^[a-f0-9]{128}$/i, digest: (s) => createHash("sha512").update(s).digest("hex") },
  { name: "sha3-256", re: /^[a-f0-9]{64}$/i, digest: (s) => createHash("sha3-256").update(s).digest("hex") },
];

interface Parsed {
  readonly algorithm: string;
  readonly hex?: string;
  readonly salt?: string;
  readonly iter?: number;
  readonly note?: string;
  readonly verify?: (pw: string) => boolean;
}

const parseHash = (h: string): Parsed => {
  const django = /^pbkdf2_sha256\$(\d+)\$([^$]+)\$([^$]+)$/.exec(h);
  if (django) {
    const iter = Number(django[1]);
    const salt = django[2] ?? "";
    const want = Buffer.from(django[3] ?? "", "base64");
    return { algorithm: `pbkdf2-sha256 (${iter} it)`, salt, iter, verify: (pw) => { try { const got = pbkdf2Sync(pw, salt, iter, want.length, "sha256"); return got.length === want.length && timingSafeEqual(got, want); } catch { return false; } } };
  }
  const scrypt = /^scrypt\$([^$]+)\$([^$]+)$/.exec(h);
  if (scrypt) {
    const salt = scrypt[1] ?? "";
    const want = Buffer.from(scrypt[2] ?? "", "hex");
    return { algorithm: "scrypt", salt, verify: (pw) => { try { const got = scryptSync(pw, salt, want.length); return got.length === want.length && timingSafeEqual(got, want); } catch { return false; } } };
  }
  if (/^\$2[aby]\$/.test(h)) return { algorithm: "bcrypt", note: "identified, verify externally (hashcat/htpasswd)" };
  if (/^\$argon2/.test(h)) return { algorithm: h.split("$")[1] ?? "argon2", note: "identified, verify externally" };
  for (const a of ALGOS) if (a.re.test(h)) return { algorithm: a.name, hex: h.toLowerCase() };
  return { algorithm: "unknown" };
};

export const crackHashes = async (input: CrackInput): Promise<CrackResult> => {
  const start = Date.now();
  const budget = (input.maxSeconds ?? 30) * 1000;
  const words = [...(input.wordlist?.length ? input.wordlist : WORDS)];
  const useRules = input.rules !== false;
  const cracked: Cracked[] = [];
  const unsupported: CrackResult["unsupported"] = [];
  let attempts = 0;

  const parsed = input.hashes.map((h) => ({ hash: h.trim(), p: parseHash(h.trim()) })).filter((x) => x.hash);
  for (const { hash, p } of parsed) {
    if (!p.verify && !p.hex) { unsupported.push({ hash, algorithm: p.algorithm, note: p.note ?? "no in-process verifier" }); continue; }
    let found: Cracked | null = null;
    const combos = useRules && !p.verify;
    for (const word of words) {
      if (Date.now() - start > budget) break;
      for (const { cand, rule } of candidates(word, combos)) {
        attempts++;
        let hit = false;
        if (p.verify) hit = p.verify(cand);
        else if (p.hex) {
          for (const a of ALGOS) {
            if (!a.digest || a.name !== p.algorithm) continue;
            if (a.digest(cand) === p.hex) { hit = true; break; }
          }
          // sha256 and sha3-256 share a regex — try both when the named one misses
          if (!hit && p.algorithm === "sha256") hit = createHash("sha3-256").update(cand).digest("hex") === p.hex;
        }
        if (hit) { found = { hash, algorithm: p.algorithm, plaintext: cand, rule, attempts }; break; }
      }
      if (found) break;
    }
    if (found) cracked.push(found);
  }
  const elapsedMs = Date.now() - start;
  const { writeArtifact } = await import("../adapters/artifacts.js");
  const body = JSON.stringify({ cracked, unsupported, attempts, elapsedMs }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "hash_crack.json", body);
  return { cracked, unsupported, attempts, elapsedMs, artifacts: [artifact] };
};
