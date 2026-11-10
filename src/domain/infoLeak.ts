import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Information-disclosure surface: stack traces / internal paths in
 *  errors, verbatim backend banners, JWT/API keys echoed in responses,
 *  debug/profiling endpoints, directory listings, .git/.env artifacts,
 *  and version headers. */

export interface LeakInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface LeakFinding {
  readonly kind: string;
  readonly where: string;
  readonly evidence: string;
  readonly severity: "high" | "medium" | "low";
}
export interface LeakResult {
  readonly probed: number;
  readonly findings: LeakFinding[];
  readonly artifacts: { path: string; bytes: number }[];
}

const PATHS = ["/.env", "/.git/config", "/server-status", "/server-info", "/phpinfo.php", "/actuator/env", "/actuator/heapdump", "/debug/vars", "/metrics", "/swagger.json", "/api-docs", "/graphql", "/console", "/admin/config", "/trace", "/.DS_Store", "/web.config", "/backup.sql", "/debug", "/_debug/paths", "/elmah.axd", "/trace.axd"];

export const probeInfoLeak = async (input: LeakInput): Promise<LeakResult> => {
  const base = input.baseUrl.replace(/\/$/, "");
  const findings: LeakFinding[] = [];
  const opts = { cookie: input.cookie, headers: input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 };
  let probed = 0;
  // 1) 敏感路径存在性(200且非SPA fallback)
  const spaProbe = await fetchUrl(`${base}/${Math.random().toString(36).slice(2)} nonexistent`, opts); probed++;
  const spaLen = spaProbe.bytes;
  const spaBody = spaProbe.body.slice(0, 200);
  for (const p of PATHS) {
    try {
      const r = await fetchUrl(`${base}${p}`, opts); probed++;
      if (r.status === 200) {
        const sameAsSpa = r.bytes === spaLen && r.body.slice(0, 200) === spaBody;
        if (!sameAsSpa && r.bytes > 20) {
          const kind = p.includes(".env") ? "env-file" : p.includes(".git") ? "git-config" : p.includes("heapdump") ? "heapdump" : p.includes("actuator") ? "spring-actuator" : p.includes("server-status") ? "apache-status" : p.includes("phpinfo") ? "phpinfo" : p.includes("swagger") || p.includes("api-docs") ? "api-spec" : "sensitive-path";
          const sev: LeakFinding["severity"] = ["env-file", "git-config", "heapdump"].includes(kind) ? "high" : kind === "spring-actuator" || kind === "apache-status" || kind === "phpinfo" ? "medium" : "low";
          findings.push({ kind, where: p, evidence: `200 ${r.bytes}B distinct from SPA fallback`, severity: sev });
        }
      }
    } catch { /* skip */ }
  }
  // 2) 错误页信息量(触发500)
  try {
    const r = await fetchUrl(`${base}/%00`, opts); probed++;
    const stacky = /at\s+\S+\s+\(.*?\:\d+\:\d+\)|Traceback \(most recent call|\.java:\d+|\.php on line \d+|System\.\w+Exception/i.test(r.body);
    if (stacky) findings.push({ kind: "stack-trace", where: "/%00", evidence: `error page leaks stack frame (${r.status})`, severity: "medium" });
    if (/\/(home|root|var|usr|opt|app|srv)\/[a-z0-9_\/.-]{3,}/i.test(r.body)) findings.push({ kind: "internal-path", where: "/%00", evidence: "absolute filesystem path in error output", severity: "low" });
  } catch { /* skip */ }
  // 3) 主页头/banner
  try {
    const r = await fetchUrl(base, opts); probed++;
    for (const [h, v] of Object.entries(r.headers)) {
      const vs = String(v);
      if (/^(?:x-powered-by|x-aspnet-version|x-generator|server)$/i.test(h) && vs.length > 0) findings.push({ kind: "banner", where: `header:${h}`, evidence: vs.slice(0, 60), severity: "low" });
      if (h.toLowerCase() === "via" || h.toLowerCase() === "x-varnish") findings.push({ kind: "proxy-banner", where: `header:${h}`, evidence: vs.slice(0, 60), severity: "low" });
    }
    if (/(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-]{12,}['"]/i.test(r.body)) findings.push({ kind: "inline-secret", where: "body", evidence: "credential-shaped literal in HTML", severity: "high" });
  } catch { /* skip */ }
  const artifacts = [
    await writeArtifact(input.outputRoot, "info_leak.json", JSON.stringify({ probed, findings }, null, 2)),
    await writeArtifact(input.outputRoot, "info_leak.md", ["# Information disclosure", "", ...(["high", "medium", "low"] as const).flatMap(sev => findings.filter(f => f.severity === sev).map(f => `- **[${f.severity}] ${f.kind}** ${f.where} — ${f.evidence}`))].join("\n")),
  ];
  return { probed, findings, artifacts };
};
