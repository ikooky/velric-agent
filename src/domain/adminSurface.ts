import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

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

/** Body signature robust to embedded random tokens (mirrors pathProbe):
 *  SPA catch-alls answer 200 to /admin too — a signature identical to the
 *  random-path baseline is the soft-404 page, not a real panel. */
const sigOf = (status: number, bytes: number, contentType: string, body: string): string => {
  const kind = contentType.includes("json") ? "json" : contentType.includes("html") ? "html" : "other";
  const band = bytes < 512 ? "s" : bytes < 2048 ? "m" : bytes < 16384 ? "l" : "xl";
  const marker = kind === "json"
    ? (body.match(/"(?:error|message|code|msg|status)"\s*:/) ?? [""])[0]
    : kind === "html"
      ? (body.match(/<(?:title|h1)[^>]*>([^<]{0,60})/) ?? [""])[0]
      : "";
  return `${status}:${kind}:${band}:${marker}`;
};

export const probeAdminSurface = async (input: AdminSurfaceInput): Promise<AdminSurfaceResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, cookie: input.cookie, headers: input.headers };
  const base = input.baseUrl.replace(/\/+$/, "");

  // Soft-404 calibration: 3 random paths → the catch-all signature to EXCLUDE.
  const softSigs = new Set<string>();
  for (const rnd of ["/zzqq-velric-404-a", "/zzqq-velric-404-b", "/zzqq-velric-404-c"]) {
    const r = await fetchUrl(base + rnd, opts);
    if (r.status > 0) softSigs.add(sigOf(r.status, r.bytes, r.contentType, r.body));
  }

  const found: AdminSurfaceFound[] = [];
  let probed = 0;

  for (const s of SURFACES) {
    const url = `${base}${s.path}`;
    probed += 1;
    const r = await fetchUrl(url, { ...opts, method: "GET" });
    const isSoft404 = softSigs.has(sigOf(r.status, r.bytes, r.contentType, r.body));
    if (r.status >= 200 && r.status < 300 && r.bytes > 0 && !isSoft404) {
      found.push({ url, kind: s.kind, status: r.status, bytes: r.bytes, evidence: s.evidence?.(r.body.slice(0, 4096)) });
      for (const sub of s.subs ?? []) {
        const su = `${base}${sub.path}`;
        probed += 1;
        const sr = await fetchUrl(su, { ...opts, method: "GET" });
        const subSoft = softSigs.has(sigOf(sr.status, sr.bytes, sr.contentType, sr.body));
        if (sr.status >= 200 && sr.status < 300 && sr.bytes > 0 && !subSoft) {
          found.push({ url: su, kind: sub.kind, status: sr.status, bytes: sr.bytes, evidence: sub.evidence?.(sr.body.slice(0, 4096)) });
        }
      }
    }
  }

  const body = JSON.stringify({ probed, found }, null, 2);
  const path = join(input.outputRoot, "admin_surface.json");
  await writeFile(path, body, "utf8");
  return { probed, found, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
