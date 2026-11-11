import { connect } from "node:net";
import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Unauthenticated infrastructure services — the direct "backstage" class of
 *  exposure: Redis with no AUTH, Docker API without TLS/auth, etcd/Consul KV
 *  dumps, unsecured Kubernetes API, Elasticsearch indices, Prometheus targets
 *  and config (often carrying scrape credentials), Nacos config store,
 *  RabbitMQ guest:guest, MinIO health, CouchDB admin-party, Kibana.
 *  One TCP/HTTP probe per service; a positive is proof-of-access, not a guess. */

export type ServiceId = "redis" | "docker" | "etcd" | "consul" | "nacos" | "elasticsearch" | "k8s" | "prometheus" | "kibana" | "couchdb" | "rabbitmq" | "minio";

export interface ServiceSpec {
  readonly id: ServiceId;
  readonly port: number;
  readonly label: string;
}

const SERVICES: readonly ServiceSpec[] = [
  { id: "redis", port: 6379, label: "Redis (RESP INFO)" },
  { id: "docker", port: 2375, label: "Docker Engine API" },
  { id: "etcd", port: 2379, label: "etcd v2 keys" },
  { id: "consul", port: 8500, label: "Consul catalog/KV" },
  { id: "nacos", port: 8848, label: "Nacos config/service" },
  { id: "elasticsearch", port: 9200, label: "Elasticsearch indices" },
  { id: "k8s", port: 8080, label: "Kubernetes insecure API" },
  { id: "prometheus", port: 9090, label: "Prometheus targets/config" },
  { id: "kibana", port: 5601, label: "Kibana status" },
  { id: "couchdb", port: 5984, label: "CouchDB _all_dbs" },
  { id: "rabbitmq", port: 15672, label: "RabbitMQ management" },
  { id: "minio", port: 9000, label: "MinIO health" },
];

export interface ServiceUnauthInput {
  readonly host: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Override ports (tests / non-standard deployments). */
  readonly ports?: Partial<Record<ServiceId, number>>;
  /** Restrict to these service ids. */
  readonly services?: readonly string[];
}

export interface ServiceFinding {
  readonly id: ServiceId;
  readonly port: number;
  readonly state: "unauth-access" | "auth-required" | "detected" | "closed";
  readonly evidence: string;
  readonly extras?: Record<string, number | string>;
}

export interface ServiceUnauthResult {
  readonly host: string;
  readonly findings: ServiceFinding[];
  readonly artifacts: { path: string; bytes: number }[];
}

const redisProbe = async (host: string, port: number, timeoutMs: number): Promise<ServiceFinding> => {
  const r = await new Promise<{ data: string; err?: string }>((resolve) => {
    const chunks: string[] = [];
    const sock = connect({ host, port });
    const done = (err?: string): void => { clearTimeout(t); sock.removeAllListeners(); sock.destroy(); resolve({ data: chunks.join(""), err }); };
    const t = setTimeout(() => done("timeout"), timeoutMs);
    sock.setEncoding("utf8");
    sock.on("connect", () => sock.write("INFO\r\n"));
    sock.on("data", (c: string) => { chunks.push(c); if (chunks.join("").length > 16_384 || /redis_version|NOAUTH|DENIED/.test(chunks.join(""))) done(); });
    sock.on("error", (e) => done(e.message));
  });
  if (r.err && r.data === "") return { id: "redis", port, state: "closed", evidence: r.err };
  if (/NOAUTH|DENIED/i.test(r.data)) return { id: "redis", port, state: "auth-required", evidence: r.data.split("\r\n").find((l) => /NOAUTH|DENIED/i.test(l)) ?? "auth required" };
  if (/redis_version:/.test(r.data)) {
    const version = /redis_version:([^\r\n]+)/.exec(r.data)?.[1] ?? "?";
    const clients = /connected_clients:([^\r\n]+)/.exec(r.data)?.[1] ?? "?";
    const keys = /db0:keys=(\d+)/.exec(r.data)?.[1] ?? "0";
    return { id: "redis", port, state: "unauth-access", evidence: `INFO served without AUTH (version ${version})`, extras: { version, connectedClients: clients, db0Keys: keys } };
  }
  return { id: "redis", port, state: "detected", evidence: r.data.slice(0, 120) || "connected, no RESP banner" };
};

interface HttpStep { readonly path: string; readonly ok: number[]; readonly marker?: RegExp; readonly basic?: string }

const httpService = async (
  host: string, port: number, steps: readonly HttpStep[], timeoutMs: number, proxy?: string,
): Promise<{ state: ServiceFinding["state"]; hits: string[]; extras: Record<string, number | string> }> => {
  const hits: string[] = [];
  const extras: Record<string, number | string> = {};
  let anyAlive = false;
  for (const step of steps) {
    const headers: Record<string, string> = {};
    if (step.basic) headers.authorization = `Basic ${Buffer.from(step.basic).toString("base64")}`;
    const r = await fetchUrl(`http://${host}:${port}${step.path}`, { headers, maxAttempts: 1, redirect: "manual", timeoutMs, proxy, maxBytes: 512 * 1024 });
    if (r.status === 0) continue;
    anyAlive = true;
    if (step.ok.includes(r.status) && (!step.marker || step.marker.test(r.body))) {
      hits.push(`${step.path} → ${r.status}${r.body ? ` (${r.body.slice(0, 160)})` : ""}`);
      if (step.path.includes("containers")) extras.containers = (JSON.parse(r.body) as unknown[]).length;
      if (step.path.includes("images")) extras.images = (JSON.parse(r.body) as unknown[]).length;
      if (step.path.includes("_all_dbs")) extras.databases = (JSON.parse(r.body) as unknown[]).length;
      if (step.path.includes("/v2/keys")) extras.kvNodes = (r.body.match(/"key":/g) ?? []).length;
      if (step.path.includes("api/v1/pods")) extras.pods = (JSON.parse(r.body) as { items?: unknown[] }).items?.length ?? 0;
      if (step.path.includes("api/v1/secrets")) extras.secrets = (JSON.parse(r.body) as { items?: unknown[] }).items?.length ?? 0;
      if (step.path.includes("/targets")) extras.targets = (JSON.parse(r.body) as { data?: { activeTargets?: unknown[] } }).data?.activeTargets?.length ?? 0;
      if (step.path.includes("indices")) extras.indices = (JSON.parse(r.body) as unknown[]).length;
      if (step.path.includes("configs")) extras.configs = (r.body.match(/"dataId"/g) ?? []).length;
    } else if (r.status === 401 || r.status === 403) {
      if (hits.length === 0) hits.push(`${step.path} → ${r.status} (auth required)`);
    }
  }
  if (!anyAlive) return { state: "closed", hits, extras };
  if (hits.some((h) => !h.includes("auth required"))) return { state: "unauth-access", hits, extras };
  return { state: "auth-required", hits, extras };
};

const HTTP_STEPS: Partial<Record<ServiceId, { steps: HttpStep[]; authMsg: string }>> = {
  docker: { authMsg: "Docker API", steps: [
    { path: "/version", ok: [200], marker: /"ApiVersion"|"Version"/ },
    { path: "/containers/json?all=1", ok: [200] },
    { path: "/images/json", ok: [200] },
  ] },
  etcd: { authMsg: "etcd", steps: [
    { path: "/version", ok: [200], marker: /etcdserver/ },
    { path: "/v2/keys/?recursive=true", ok: [200], marker: /"node"/ },
  ] },
  consul: { authMsg: "Consul", steps: [
    { path: "/v1/status/leader", ok: [200], marker: /"/ },
    { path: "/v1/catalog/services", ok: [200], marker: /\{/ },
    { path: "/v1/kv/?recurse", ok: [200, 404] },
  ] },
  nacos: { authMsg: "Nacos", steps: [
    { path: "/nacos/v1/ns/service/list?pageNo=1&pageSize=20", ok: [200], marker: /"doms"|"count"/ },
    { path: "/nacos/v1/cs/configs?search=accurate&pageNo=1&pageSize=10", ok: [200], marker: /"pageItems"/ },
  ] },
  elasticsearch: { authMsg: "Elasticsearch", steps: [
    { path: "/_cat/indices?format=json", ok: [200], marker: /\[/ },
    { path: "/_nodes/http", ok: [200], marker: /"nodes"/ },
  ] },
  k8s: { authMsg: "Kubernetes", steps: [
    { path: "/version", ok: [200], marker: /"gitVersion"/ },
    { path: "/api/v1/pods", ok: [200], marker: /"items"/ },
    { path: "/api/v1/secrets", ok: [200], marker: /"items"/ },
  ] },
  prometheus: { authMsg: "Prometheus", steps: [
    { path: "/api/v1/targets", ok: [200], marker: /"activeTargets"/ },
    { path: "/api/v1/status/config", ok: [200], marker: /"yaml"/ },
  ] },
  kibana: { authMsg: "Kibana", steps: [
    { path: "/api/status", ok: [200], marker: /"version"|"status"/ },
  ] },
  couchdb: { authMsg: "CouchDB", steps: [
    { path: "/_all_dbs", ok: [200], marker: /\[/ },
  ] },
  rabbitmq: { authMsg: "RabbitMQ", steps: [
    { path: "/api/overview", ok: [200], marker: /"rabbitmq_version"/, basic: "guest:guest" },
  ] },
  minio: { authMsg: "MinIO", steps: [
    { path: "/minio/health/live", ok: [200] },
  ] },
};

export const probeServiceUnauth = async (input: ServiceUnauthInput): Promise<ServiceUnauthResult> => {
  const host = input.host.replace(/^https?:\/\//, "").replace(/[/:].*$/, "");
  const wanted = input.services?.length ? SERVICES.filter((s) => input.services!.includes(s.id)) : SERVICES;
  const timeoutMs = input.timeoutMs ?? 6_000;
  const findings: ServiceFinding[] = [];
  for (const spec of wanted) {
    const port = input.ports?.[spec.id] ?? spec.port;
    try {
      if (spec.id === "redis") {
        findings.push(await redisProbe(host, port, timeoutMs));
        continue;
      }
      const def = HTTP_STEPS[spec.id];
      if (!def) { findings.push({ id: spec.id, port, state: "closed", evidence: "no probe" }); continue; }
      const r = await httpService(host, port, def.steps, timeoutMs, input.proxy);
      findings.push({ id: spec.id, port, state: r.state, evidence: r.hits.length ? r.hits.join(" | ") : def.authMsg, extras: Object.keys(r.extras).length ? r.extras : undefined });
    } catch (e) {
      findings.push({ id: spec.id, port, state: "closed", evidence: (e as Error).message.slice(0, 120) });
    }
  }
  const unauth = findings.filter((f) => f.state === "unauth-access");
  const body = JSON.stringify({ host, findings, summary: { unauth: unauth.length, authRequired: findings.filter((f) => f.state === "auth-required").length } }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "service_unauth.json", body);
  return { host, findings, artifacts: [artifact] };
};
