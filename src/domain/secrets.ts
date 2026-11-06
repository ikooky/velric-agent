/** Deterministic secret/credential/PII patterns worth flagging in recon JS,
 *  response bodies, and unpacked dumps.
 *
 *  Three layers:
 *  - SECRET_PATTERNS: credential regexes (top providers with structural
 *    prefixes, high-signal subset)
 *  - PAIRED_SECRETS: co-occurrence pairing — an AWS access key id alone may be
 *    a false positive, but key id + base64 secret co-occurring in the same
 *    object/region is a confirmed credential pair
 *  - PII_PATTERNS: personally identifiable data movement (API
 *    response analysis): emails, phones, national IDs, cards, JWTs
 *
 *  All deterministic, no LLM. */

export interface SecretPattern {
  readonly name: string;
  readonly re: RegExp;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  // cloud / SaaS keys (structural prefixes)
  { name: "aws_access_key_id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/ },
  { name: "gitlab_pat", re: /\bglpat-[A-Za-z0-9_\-]{20,64}\b/ },
  { name: "slack_token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,250}\b/ },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/ },
  { name: "google_oauth", re: /\bya29\.[0-9A-Za-z_\-]{20,}\b/ },
  { name: "stripe_key", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,255}\b/ },
  { name: "twilio_key", re: /\bSK[0-9a-fA-F]{32}\b/ },
  { name: "sendgrid_key", re: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/ },
  { name: "mailgun_key", re: /\bkey-[0-9a-zA-Z]{32}\b/ },
  { name: "npm_token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: "shopify_token", re: /\bshpat_[0-9a-fA-F]{32}\b/ },
  { name: "openai_key", re: /\bsk-[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b/ },
  { name: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_\-]{24,}\b/ },
  { name: "private_key_block", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/ },
  // \b fails on empty alg=none signatures — lookahead keeps them matchable (see jwt.ts)
  { name: "jwt", re: /\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{0,}(?![A-Za-z0-9_\-])/ },
  { name: "amqp_url", re: /\bamqps?:\/\/[^\s"'>){,]{10,200}/ },
  {
    name: "db_url",
    re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|mssql|oracle):\/\/[^\s"'>){,]{5,200}/,
  },
  { name: "internal_ip", re: /\b(?:(?:10|127)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|169\.254\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b/ },
  {
    name: "internal_host",
    re: /\b(?:[-\w]+\.internal(?:\.[-\w]+)*|[-\w]+\.local(?:domain)?(?:\.[-\w]+)*|[-\w]+\.corp(?:\.[-\w]+)*)\b/,
  },
  {
    name: "generic_secret_assignment",
    re: /(?:api[_-]?key|apikey|secret|token|passwd|password)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/,
  },
];

/** Paired credential detection: a lone identifier is a
 *  weak signal; identifier + secret adjacent in the same window is a
 *  confirmed pair. Window = same JSON object or 200-char neighborhood. */
export interface PairedSecretPattern {
  readonly name: string;
  /** identifier pattern */
  readonly idRe: RegExp;
  /** secret pattern */
  readonly secretRe: RegExp;
  /** max chars between id and secret for a pair */
  readonly window: number;
}

export const PAIRED_SECRETS: readonly PairedSecretPattern[] = [
  {
    name: "aws_key_pair",
    idRe: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    secretRe: /\b[A-Za-z0-9/+=]{40}\b/,
    window: 300,
  },
  {
    name: "google_oauth_pair",
    idRe: /\b\d+-[0-9a-zA-Z_]{24,}\.apps\.googleusercontent\.com\b/,
    secretRe: /\bGOCSPX-[A-Za-z0-9_\-]{20,}\b/,
    window: 400,
  },
];

/** PII movement patterns (sensitive-data-exposure detection over
 *  recorded API responses). Structurally validated, not bare regex spam. */
export const PII_PATTERNS: readonly SecretPattern[] = [
  { name: "email", re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  // mainland-CN mobile (structural: 1[3-9] + 9 digits, not part of a longer number)
  { name: "phone_cn", re: /(?<!\d)1[3-9]\d{9}(?!\d)/ },
  { name: "phone_intl", re: /\+\d{1,3}[\s-]?\d{4,14}(?!\d)/ },
  // 16-digit cards with Luhn-adjacent spacing (13-19 digits, grouped)
  { name: "card_number", re: /\b(?:\d[ -]?){13,19}\b/ },
  { name: "cn_id_card", re: /(?<!\d)\d{17}[0-9Xx](?!\d)/ },
  { name: "iban", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/ },
  { name: "jwt_token", re: /\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}(?![A-Za-z0-9_\-])/ },
];

export interface SecretHit {
  readonly name: string;
  readonly match: string;
  readonly file: string;
}

/** Cap matches per pattern per file to keep output bounded on huge bundles. */
const MAX_PER_PATTERN = 5;

const scanWith = (
  files: readonly { path: string; text: string }[],
  patterns: readonly SecretPattern[],
): SecretHit[] => {
  const hits: SecretHit[] = [];
  for (const { path, text } of files) {
    for (const p of patterns) {
      const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
      let count = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null && count < MAX_PER_PATTERN) {
        hits.push({ name: p.name, match: m[0].slice(0, 200), file: path });
        count++;
      }
    }
  }
  return hits;
};

/** Scan for single-pattern credential hits (original scanSecrets behavior,
 *  now over the expanded pattern set). */
export const scanSecrets = (files: readonly { path: string; text: string }[]): SecretHit[] =>
  scanWith(files, SECRET_PATTERNS);

/** Scan for PII movement in response bodies / dumps. */
export const scanPii = (files: readonly { path: string; text: string }[]): SecretHit[] =>
  scanWith(files, PII_PATTERNS);

/** Paired-secret scan: only reports pairs (id + secret co-occurring within
 *  the window), drastically lower false-positive than either pattern alone. */
export const scanPairedSecrets = (files: readonly { path: string; text: string }[]): SecretHit[] => {
  const hits: SecretHit[] = [];
  for (const { path, text } of files) {
    for (const p of PAIRED_SECRETS) {
      const ids: { idx: number; val: string }[] = [];
      const idRe = new RegExp(p.idRe.source, p.idRe.flags.includes("g") ? p.idRe.flags : p.idRe.flags + "g");
      let m: RegExpExecArray | null;
      while ((m = idRe.exec(text)) !== null && ids.length < 20) ids.push({ idx: m.index, val: m[0] });
      if (ids.length === 0) continue;
      const secRe = new RegExp(p.secretRe.source, p.secretRe.flags.includes("g") ? p.secretRe.flags : p.secretRe.flags + "g");
      const seen = new Set<string>();
      while ((m = secRe.exec(text)) !== null && hits.length < 50) {
        for (const id of ids) {
          const dist = Math.abs(m.index - id.idx);
          if (dist <= p.window) {
            const key = `${p.name}:${id.val}:${m[0]}`;
            if (seen.has(key)) break;
            seen.add(key);
            hits.push({ name: p.name, match: `${id.val} + ${m[0].slice(0, 60)}`, file: path });
            break;
          }
        }
      }
    }
  }
  return hits;
};
