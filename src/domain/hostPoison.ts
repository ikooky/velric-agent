import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Host-header / password-reset poisoning surface: injectable Host,
 *  X-Forwarded-Host, X-Forwarded-Proto, X-Original-URL and their effect
 *  on absolute URLs the server generates (reset links, canonicals,
 *  redirects) — the core of reset-poisoning attacks. */

export interface HostPoisonInput {
  readonly url: string;
  readonly outputRoot: string;
  readonly canaryHost?: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface PoisonCase {
  readonly vector: string;
  readonly status: number;
  /** canary host appeared in: body absolute URL / Location / email-sent semantic */
  readonly where: string[];
  readonly bodyPrefix: string;
}
export interface HostPoisonResult {
  readonly probed: number;
  readonly poisoned: PoisonCase[];
  readonly cases: PoisonCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

export const probeHostPoison = async (input: HostPoisonInput): Promise<HostPoisonResult> => {
  const canary = input.canaryHost ?? "poison-canary.evil.example";
  const vectors: { vector: string; headers: Record<string, string> }[] = [
    { vector: "host", headers: { host: canary } },
    { vector: "x-forwarded-host", headers: { "x-forwarded-host": canary } },
    { vector: "x-forwarded-host+proto", headers: { "x-forwarded-host": canary, "x-forwarded-proto": "https" } },
    { vector: "x-original-host", headers: { "x-original-host": canary } },
    { vector: "x-host", headers: { "x-host": canary } },
    { vector: "x-forwarded-server", headers: { "x-forwarded-server": canary } },
    { vector: "x-rewrite-url", headers: { "x-rewrite-url": `//${canary}/p` } },
    { vector: "forwarded", headers: { forwarded: `host=${canary}` } },
    { vector: "host+xfh", headers: { host: canary, "x-forwarded-host": canary } },
  ];
  const cases: PoisonCase[] = [];
  const poisoned: PoisonCase[] = [];
  for (const v of vectors) {
    try {
      const r = await fetchUrl(input.url, { headers: { ...(input.headers ?? {}), ...v.headers }, cookie: input.cookie, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000, maxAttempts: 1 });
      const where: string[] = [];
      if (r.body.includes(canary)) where.push("body");
      for (const [hk, hv] of Object.entries(r.headers)) if (String(hv).includes(canary)) where.push(`header:${hk}`);
      // 绝对URL生成位: 链接/canonical/action
      const absUrl = new RegExp(`https?://${canary.replace(/\./g, "\\.")}/[^"'\s<>]{0,80}`).test(r.body) || Object.values(r.headers).some(hv => new RegExp(`https?://${canary.replace(/\./g, "\\.")}`).test(String(hv)));
      const c: PoisonCase = { vector: v.vector, status: r.status, where, bodyPrefix: r.body.slice(0, 100) };
      cases.push(c);
      if (where.length > 0 && absUrl) poisoned.push({ ...c, where: [...where, "absolute-url"] });
      else if (where.length > 0) poisoned.push(c);
    } catch { cases.push({ vector: v.vector, status: 0, where: [], bodyPrefix: "" }); }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "host_poison_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "host_poison.md", ["# Host-header / reset poisoning surface", "", `poisoned vectors: ${poisoned.length}/${cases.length}`, "", ...poisoned.map(p => `- **${p.vector}** → canary reflected in ${p.where.join(", ")} — server builds absolute URLs from attacker-controlled input`)].join("\n")),
  ];
  return { probed: cases.length, poisoned, cases, artifacts };
};
