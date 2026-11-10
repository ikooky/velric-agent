import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Password policy surface: whether registration/password-change accepts
 *  trivially weak passwords (empty, "1", "password", top-100 common),
 *  and whether changed-password reuse / case-fold variants slip through. */

export interface PpInput {
  readonly url: string;
  readonly bodyTemplate: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface PpCase {
  readonly password: string;
  readonly kind: string;
  readonly status: number;
  readonly accepted: boolean;
  readonly bodyPrefix: string;
}
export interface PpResult {
  readonly probed: number;
  readonly weakAccepted: PpCase[];
  readonly cases: PpCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const CANDIDATES: { p: string; kind: string }[] = [
  { p: "", kind: "empty" },
  { p: "1", kind: "single-char" },
  { p: "a", kind: "single-char" },
  { p: "123456", kind: "top-common" },
  { p: "password", kind: "top-common" },
  { p: "1234567890", kind: "numeric-only" },
  { p: "aaaaaaaa", kind: "repeat" },
  { p: "qwertyuiop", kind: "keyboard-walk" },
  { p: "aaaaaaaaaaaaaaa1", kind: "length-16-no-complexity" },
  { p: "Abcdef1!", kind: "minimal-complexity" },
];

export const probePassPolicy = async (input: PpInput): Promise<PpResult> => {
  const hdrs = { "content-type": "application/json", ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) };
  const cases: PpCase[] = [];
  const weakAccepted: PpCase[] = [];
  let seq = 0;
  for (const c of CANDIDATES) {
    const body = input.bodyTemplate.replaceAll("{PASS}", c.p).replaceAll("{UNIQ}", `${Date.now()}-${seq++}`);
    try {
      const r = await fetchUrl(input.url, { method: "POST", body, cookie: input.cookie, headers: hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 });
      const accepted = r.status >= 200 && r.status < 300 && !/weak|policy|short|length|at least|must contain|invalid password|too common|breach/i.test(r.body.slice(0, 400));
      const pc: PpCase = { password: c.p === "" ? "(empty)" : c.p, kind: c.kind, status: r.status, accepted, bodyPrefix: r.body.slice(0, 80) };
      cases.push(pc);
      if (accepted && ["empty", "single-char", "top-common", "numeric-only", "repeat", "keyboard-walk"].includes(c.kind)) weakAccepted.push(pc);
    } catch { cases.push({ password: c.p, kind: c.kind, status: 0, accepted: false, bodyPrefix: "" }); }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "pass_policy.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "pass_policy.md", ["# Password policy", "", `weak passwords accepted: ${weakAccepted.length}/${cases.length}`, "", ...weakAccepted.map(w => `- **${w.kind}** \`${w.password}\` accepted (${w.status})`)].join("\n")),
  ];
  return { probed: cases.length, weakAccepted, cases, artifacts };
};
