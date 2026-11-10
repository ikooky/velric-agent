import { fetchUrl } from "../adapters/http.js";
import { normalizeBody, charSimilarity } from "./normalize.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Privilege-escalation parameter probe: role/admin/admin flag params that,
 *  when set by a low-priv session (or anonymous), change the response
 *  semantics — self-registration role injection, profile-update admin flag,
 *  API role claim. Differential verdicts against baseline. */

export interface RoleInput {
  readonly url: string;
  readonly method?: string;
  readonly bodyTemplate?: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** extra field names to test beyond defaults */
  readonly fields?: readonly string[];
}
export interface RoleCase {
  readonly field: string;
  readonly value: string;
  readonly status: number;
  readonly bodyPrefix: string;
  readonly accepted: boolean;
  readonly sim: number;
}
export interface RoleResult {
  readonly probed: number;
  readonly findings: { field: string; value: string; status: number; evidence: string }[];
  readonly cases: RoleCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const ROLE_FIELDS = ["role", "roles", "isAdmin", "is_admin", "admin", "adminFlag", "privilege", "privileges", "permissions", "perms", "userType", "user_type", "accountType", "account_type", "level", "accessLevel", "access_level", "groupId", "group_id", "team", "authorities", "claims", "scope"];
const ROLE_VALUES = ["admin", "administrator", "root", "superuser", "1", "true", "100", "*"];

export const probeRoleEscalation = async (input: RoleInput): Promise<RoleResult> => {
  const method = input.method ?? "POST";
  const fields = [...new Set([...(input.fields ?? []), ...ROLE_FIELDS])];
  const send = async (body: string | undefined): Promise<{ status: number; body: string }> => {
    const r = await fetchUrl(input.url, { method, body, cookie: input.cookie, headers: input.bodyTemplate || body ? { "content-type": "application/json", ...(input.headers ?? {}) } : input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000 });
    return { status: r.status, body: r.body.slice(0, 3000) };
  };
  let template: Record<string, unknown> = {};
  try { if (input.bodyTemplate) template = JSON.parse(input.bodyTemplate) as Record<string, unknown>; } catch { /* raw */ }
  const baseline = await send(input.bodyTemplate ?? undefined);
  // 回显型API对照: 无意义字段同样被接受+响应变化 → 响应差异只反映"字段被存储", 不反映权限语义
  const controlPayload = JSON.stringify({ ...template, zzqq_nonsense_probe: "1" });
  const control = await send(controlPayload);
  const controlSim = charSimilarity(normalizeBody(baseline.body), normalizeBody(control.body));
  const echoLike = controlSim < 0.95; // 对照字段也导致分叉 = 回显型, 提高报告门槛
  const cases: RoleCase[] = [];
  const findings: RoleResult["findings"] = [];
  for (const f of fields) {
    for (const v of ROLE_VALUES) {
      const body = JSON.stringify({ ...template, [f]: v === "true" ? true : v === "1" || v === "100" ? Number(v) : v });
      const r = await send(body);
      const accepted = !/error|invalid|denied|forbidden|not allowed|unknown field|unprocessable/i.test(r.body.slice(0, 500)) && r.status < 400;
      const sim = charSimilarity(normalizeBody(baseline.body), normalizeBody(r.body));
      cases.push({ field: f, value: v, status: r.status, bodyPrefix: r.body.slice(0, 120), accepted, sim });
      // 接受 + 响应语义变化 = 提权注入候选; 回显型API要求更强信号(状态码变化或值被显式回显)
      // 回显型API: 值被存储只代表存储语义; 可信信号 = 状态码变化 或 权威结论词(非字段名回显)
      if (accepted && (!echoLike ? sim < 0.95 : r.status !== baseline.status)) findings.push({ field: f, value: v, status: r.status, evidence: echoLike ? `echo-type API: status ${baseline.status}→${r.status} on role field injection` : `field accepted (${r.status}), response diverged from baseline (sim=${sim.toFixed(3)}) — role semantics likely applied` });
    }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "role_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "role_findings.md", ["# Privilege escalation surface", "", ...findings.map(f => `- **${f.field}=${f.value}** — ${f.evidence}`)].join("\n") || "# Privilege escalation surface\n\n- no accepted role field variants"),
  ];
  return { probed: cases.length, findings, cases, artifacts };
};
