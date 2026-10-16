import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { discoveryOrigin, discoverySignature, stableDiscoverySignatures } from "./pathProbe.js";

/** Framework admin-surface discovery: well-known unauthenticated management
 *  endpoints (Spring actuator, swagger/openapi, druid, nacos, eureka,
 *  grafana/kibana/jenkins consoles). Detection only — presence + status +
 *  key sub-endpoint exposure (env/heapdump/health), no exploitation. */

export interface AdminSurfaceInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface AdminSurfaceFound {
  readonly url: string;
  readonly kind: string;
  readonly status: number;
  readonly bytes: number;
  readonly evidence?: string;
}

export interface AdminSurfaceResult {
  readonly probed: number;
  readonly found: AdminSurfaceFound[];
  /** Reachable panels without verified product content — leads, not findings. */
  readonly candidates: { url: string; reason: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

interface Sub { readonly path: string; readonly kind: string; readonly evidence?: (body: string) => string | undefined }
interface Surface { readonly path: string; readonly kind: string; readonly evidence?: (body: string) => string | undefined; readonly subs?: Sub[] }

const SENSITIVE_RE = /password|secret|key|token/i;

const SURFACES: Surface[] = [
  { path: "/actuator", kind: "spring-actuator", subs: [
    { path: "/actuator/env", kind: "actuator-env", evidence: (b) => (SENSITIVE_RE.test(b) ? `credential-looking keys in env (len ${b.length})` : undefined) },
    { path: "/actuator/heapdump", kind: "actuator-heapdump", evidence: (b) => (b.length > 1000 ? `heapdump readable (${b.length}B)` : undefined) },
    { path: "/actuator/health", kind: "actuator-health" },
    { path: "/actuator/mappings", kind: "actuator-mappings", evidence: (b) => (/GET|POST/.test(b) ? `route map leak (${b.length}B)` : undefined) },
    { path: "/actuator/configprops", kind: "actuator-configprops", evidence: (b) => (SENSITIVE_RE.test(b) ? `config properties with sensitive keys (len ${b.length})` : undefined) },
  ] },
  { path: "/swagger", kind: "swagger" },
  { path: "/swagger-ui.html", kind: "swagger-ui" },
  { path: "/swagger-ui/index.html", kind: "swagger-ui" },
  { path: "/v3/api-docs", kind: "openapi-v3", evidence: (b) => (b.trim().startsWith("{") ? "openapi json readable" : undefined) },
  { path: "/v2/api-docs", kind: "openapi-v2", evidence: (b) => (b.trim().startsWith("{") ? "openapi json readable" : undefined) },
  { path: "/openapi.json", kind: "openapi" },
  { path: "/api-docs", kind: "api-docs" },
  { path: "/druid/index.html", kind: "druid-console" },
  { path: "/nacos", kind: "nacos-console", subs: [
    { path: "/nacos/v1/console/namespaces", kind: "nacos-namespaces", evidence: (b) => (b.includes("namespace") ? "namespaces readable" : undefined) },
  ] },
  { path: "/eureka/apps", kind: "eureka-registry", evidence: (b) => (b.includes("<applications>") ? "service registry readable" : undefined) },
  { path: "/grafana", kind: "grafana" },
  { path: "/kibana", kind: "kibana" },
  { path: "/kibana/app/home", kind: "kibana" },
  { path: "/jenkins/login", kind: "jenkins" },
  { path: "/console", kind: "console-generic" },
  { path: "/admin", kind: "admin-generic" },
  { path: "/manager/html", kind: "tomcat-manager" },
  { path: "/weblogic/console", kind: "weblogic-console" },
  { path: "/_cat/indices", kind: "elasticsearch-cat" },
  { path: "/api/v1/pods", kind: "k8s-pods" },
  { path: "/version", kind: "version-endpoint" },
  { path: "/metrics", kind: "metrics-endpoint" },
];

const surfaceEvidence = (kind: string, body: string): string | undefined => {
  const text = body.slice(0, 262144);
  if (kind.startsWith("openapi") || kind === "api-docs") {
    try {
      const data = JSON.parse(text) as Record<string, unknown>;
      if (data && typeof data === "object" && (typeof data.openapi === "string" || typeof data.swagger === "string") && data.paths && typeof data.paths === "object") return "openapi document with paths";
    } catch { /* HTML UI is checked below */ }
  }
  const patterns: Record<string, RegExp> = {
    "spring-actuator": /"_links"\s*:\s*\{[\s\S]*"(?:health|self)"\s*:/,
    "actuator-env": /"propertySources"\s*:/,
    "actuator-health": /"status"\s*:\s*"(?:UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"/,
    "actuator-mappings": /"(?:contexts|dispatcherServlets)"\s*:/,
    "actuator-configprops": /"(?:contexts|beans)"\s*:/,
    "actuator-heapdump": /^JAVA PROFILE 1\.0/,
    "swagger": /swagger-ui|SwaggerUIBundle|swagger-ui-bundle/i,
    "swagger-ui": /swagger-ui|SwaggerUIBundle|swagger-ui-bundle/i,
    "druid-console": /Druid Stat|druid\.js|Druid Monitor/i,
    "nacos-console": /nacos.*(?:console|login)|nacos-logo/i,
    "nacos-namespaces": /"namespace(?:ShowName)?"\s*:/,
    "eureka-registry": /<applications(?:\s|>)/,
    "grafana": /grafanaBootData|grafana-app/i,
    "kibana": /kbn-injected-metadata|kibanaLegacy/i,
    "jenkins": /jenkins\.js|Jenkins-Crumb|jenkins-head-icon/i,
    "tomcat-manager": /Tomcat Web Application Manager/i,
    "weblogic-console": /WebLogic Server Administration Console/i,
    "elasticsearch-cat": /\b(?:green|yellow|red)\s+(?:open|close)\s+/,
    "k8s-pods": /"kind"\s*:\s*"PodList"/,
    "metrics-endpoint": /^# (?:HELP|TYPE) /m,
    "version-endpoint": /"(?:version|buildVersion)"\s*:\s*"[0-9]/,
  };
  return patterns[kind]?.test(text) ? `${kind} product content` : undefined;
};


export const probeAdminSurface = async (input: AdminSurfaceInput): Promise<AdminSurfaceResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, cookie: input.cookie, headers: input.headers, redirect: "manual" as const };
  const base = discoveryOrigin(input.baseUrl);

  // Soft-404 calibration: 3 random paths → the catch-all signature to EXCLUDE.
  const baselines = [];
  for (let i = 0; i < 3; i++) baselines.push(await fetchUrl(new URL(`/zzqq-${randomUUID()}`, base).href, opts));
  const softSigs = stableDiscoverySignatures(baselines);

  const found: AdminSurfaceFound[] = [];
  const candidates: { url: string; reason: string }[] = [];
  let probed = 0;

  for (const s of SURFACES) {
    const url = `${base}${s.path}`;
    probed += 1;
    const r = await fetchUrl(url, { ...opts, method: "GET" });
    const isSoft404 = softSigs.has(discoverySignature(r));
    const evidence = surfaceEvidence(s.kind, r.body);
    const reachable = r.status >= 200 && r.status < 300 && r.bytes > 0 && !isSoft404 && r.complete !== false && !r.truncated && !r.error;
    if (reachable && evidence) {
      found.push({ url, kind: s.kind, status: r.status, bytes: r.bytes, evidence: s.evidence?.(r.body.slice(0, 4096)) ?? evidence });
    } else if (reachable && !evidence && s.kind.endsWith("console") || (reachable && !evidence && ["admin-generic", "console-generic"].includes(s.kind))) {
      // A reachable panel without recognized product content is a LEAD, not a
      // finding (login walls look exactly like this) — preserved with its
      // reason instead of silently dropped.
      candidates.push({ url, reason: "product-content-unverified" });
    }
    // Subpaths are probed INDEPENDENTLY of the parent: a locked-down /actuator
    // with an exposed /actuator/env is precisely the misconfiguration class
    // this probe exists to find.
    for (const sub of s.subs ?? []) {
      const su = `${base}${sub.path}`;
      probed += 1;
      const sr = await fetchUrl(su, { ...opts, method: "GET" });
      const subSoft = softSigs.has(discoverySignature(sr));
      const subEvidence = surfaceEvidence(sub.kind, sr.body);
      const subReachable = sr.status >= 200 && sr.status < 300 && sr.bytes > 0 && !subSoft && sr.complete !== false && !sr.truncated && !sr.error;
      if (subReachable && subEvidence) {
        found.push({ url: su, kind: sub.kind, status: sr.status, bytes: sr.bytes, evidence: sub.evidence?.(sr.body.slice(0, 4096)) ?? subEvidence });
      } else if (subReachable && !subEvidence) {
        candidates.push({ url: su, reason: "product-content-unverified" });
      }
    }
  }

  const body = JSON.stringify({ probed, found, candidates }, null, 2);
  const path = join(input.outputRoot, "admin_surface.json");
  await writeFile(path, body, "utf8");
  return { probed, found, candidates, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
