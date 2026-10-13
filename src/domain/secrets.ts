/** Deterministic secret/credential patterns worth flagging in recon JS. */

export interface SecretPattern {
  readonly name: string;
  readonly re: RegExp;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { name: "aws_access_key_id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/ },
  { name: "slack_token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,250}\b/ },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/ },
  { name: "private_key_block", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b/ },
  { name: "amqp_url", re: /\bamqps?:\/\/[^\s"'>){,]{10,200}/ },
  {
    name: "db_url",
    re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s"'>){,]{5,200}/,
  },
  { name: "internal_ip", re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/ },
  {
    name: "internal_host",
    re: /\b(?:[-\w]+\.internal(?:\.[-\w]+)*|[-\w]+\.local(?:domain)?(?:\.[-\w]+)*|[-\w]+\.corp(?:\.[-\w]+)*)\b/,
  },
  {
    name: "generic_secret_assignment",
    re: /(?:api[_-]?key|apikey|secret|token|passwd|password)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/,
  },
];

export interface SecretHit {
  readonly name: string;
  readonly match: string;
  readonly file: string;
}

/** Cap matches per pattern per file to keep output bounded on huge bundles. */
const MAX_PER_PATTERN = 5;

export const scanSecrets = (files: readonly { path: string; text: string }[]): SecretHit[] => {
  const hits: SecretHit[] = [];
  for (const { path, text } of files) {
    for (const p of SECRET_PATTERNS) {
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
