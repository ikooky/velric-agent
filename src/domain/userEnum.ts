import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { charSimilarity, normalizeBody } from "./normalize.js";

/** Account enumeration oracles. The world splits in two: servers that answer
 *  "user exists" differently for a valid account (status or text), and servers
 *  that don't. Two baselines — a known-good account with a wrong password and
 *  a random account — decide per candidate; "same as both" is logged as a
 *  blind oracle, not a false positive. Works on login, registration and reset
 *  forms; registration enumerates the opposite way (taken vs available). */

export type EnumMode = "login" | "register" | "reset";

export interface EnumInput {
  readonly url: string;
  readonly bodyTemplate: string;
  readonly mode: EnumMode;
  /** Known-valid account (baseline). */
  readonly knownUser: string;
  readonly candidates: readonly string[];
  readonly outputRoot: string;
  readonly password?: string;
  readonly contentType?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly headers?: Record<string, string>;
}

export interface EnumRow {
  readonly user: string;
  readonly status: number;
  readonly similarityKnown: number;
  readonly similarityRandom: number;
  readonly verdict: "exists" | "absent" | "ambiguous";
  readonly evidence: string;
}

export interface EnumResult {
  readonly mode: EnumMode;
  readonly oracle: boolean;
  readonly rows: EnumRow[];
  readonly existing: readonly string[];
  readonly artifacts: { path: string; bytes: number }[];
}

const VALID_HINTS = /(already (?:registered|taken|exists)|e-?mail (?:already )?(?:in use|exists)|user(?:name)? (?:already )?(?:taken|exists)|account (?:already )?exists|reset (?:link|email) (?:sent|has been sent)|check your (?:email|inbox))/i;
const ABSENT_HINTS = /(not found|no (?:such )?(?:user|account)|unknown (?:user|account)|does ?n[o']t exist|unregistered|no account)/i;

export const probeUserEnum = async (input: EnumInput): Promise<EnumResult> => {
  const ct = input.contentType ?? (input.bodyTemplate.trim().startsWith("{") ? "application/json" : "application/x-www-form-urlencoded");
  const headers = (): Record<string, string> => ({ "content-type": ct, ...(input.headers ?? {}) });
  const send = async (user: string): Promise<{ status: number; body: string }> => {
    const body = input.bodyTemplate
      .replaceAll("{USER}", encodeURIComponent(user))
      .replaceAll("{EMAIL}", encodeURIComponent(user))
      .replaceAll("{PASS}", encodeURIComponent(input.password ?? "Velric!wrong1"));
    const r = await fetchUrl(input.url, { method: "POST", body, headers: headers(), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 256 * 1024 });
    return { status: r.status, body: r.body };
  };

  const known = await send(input.knownUser);
  const random = await send(`velric-nouser-${Date.now().toString(36)}@invalid.test`);
  const knownNorm = normalizeBody(known.body);
  const randomNorm = normalizeBody(random.body);
  const knownValidish = VALID_HINTS.test(known.body) || known.status !== random.status;
  const oracle = known.status !== random.status || charSimilarity(knownNorm, randomNorm) < 0.98;
  const rows: EnumRow[] = [];
  const existing: string[] = [];

  for (const user of input.candidates) {
    const r = await send(user);
    const simKnown = charSimilarity(normalizeBody(r.body), knownNorm);
    const simRandom = charSimilarity(normalizeBody(r.body), randomNorm);
    const hintValid = VALID_HINTS.test(r.body);
    const hintAbsent = ABSENT_HINTS.test(r.body);
    let verdict: EnumRow["verdict"] = "ambiguous";
    if (hintValid) verdict = "exists";
    else if (hintAbsent) verdict = "absent";
    else if (oracle && simKnown > simRandom + 0.02) verdict = "exists";
    else if (oracle && simRandom > simKnown + 0.02) verdict = "absent";
    else if (oracle && r.status === known.status && knownValidish) verdict = "exists";
    if (verdict === "exists") existing.push(user);
    rows.push({ user, status: r.status, similarityKnown: Number(simKnown.toFixed(3)), similarityRandom: Number(simRandom.toFixed(3)), verdict, evidence: hintValid ? "valid-user message" : hintAbsent ? "not-found message" : `sim known ${simKnown.toFixed(2)} vs random ${simRandom.toFixed(2)}, status ${r.status}` });
  }

  const body = JSON.stringify({ mode: input.mode, oracle, known: { status: known.status, body: known.body.slice(0, 200) }, random: { status: random.status, body: random.body.slice(0, 200) }, rows }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "user_enum.json", body);
  return { mode: input.mode, oracle, rows, existing, artifacts: [artifact] };
};
