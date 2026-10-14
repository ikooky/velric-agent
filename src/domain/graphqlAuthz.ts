import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/** GraphQL field-level authorization: after graphql_deep builds the schema,
 *  attempt every mutation/query against the endpoint anonymously and with a
 *  low-priv token, flagging dangerous operations reachable without auth
 *  (introspection was only the first layer). */

export interface GraphqlAuthzInput {
  readonly endpoint: string;
  /** graphql_schema.txt or graphql_deep.json from graphql_deep. */
  readonly schemaFile: string;
  readonly outputRoot: string;
  /** low-priv token (Bearer). Anonymous pass runs always. */
  readonly token?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxFields?: number;
}

export interface GraphqlAuthzResult {
  readonly probed: number;
  readonly anonymous: { field: string; kind: "query" | "mutation"; status: number; errors?: string; dataLeak: boolean }[];
  readonly lowPriv: { field: string; kind: "query" | "mutation"; status: number; dataLeak: boolean }[];
  readonly unauthed: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

const readJsonIf = async (p: string): Promise<unknown> => {
  try { return JSON.parse(await readFile(p, "utf8")); } catch { return undefined; }
};

/** Extract top-level operation names from an SDL dump or the deep-probe json. */
const extractOperations = (raw: unknown): { name: string; kind: "query" | "mutation" }[] => {
  const out: { name: string; kind: "query" | "mutation" }[] = [];
  const seen = new Set<string>();
  const push = (name: string, kind: "query" | "mutation"): void => {
    if (!name || seen.has(name)) return;
    if (/^__/.test(name)) return; // meta fields
    seen.add(name);
    out.push({ name, kind });
  };
  if (typeof raw === "string") {
    // SDL text: "type Query { field(args): Ret }"
    for (const m of raw.matchAll(/type\s+(Query|Mutation)\s*\{([^}]*)\}/g)) {
      const kind = m[1] === "Mutation" ? "mutation" : "query";
      for (const f of (m[2] ?? "").matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*(\(|:)/g)) push(f[1]!, kind);
    }
  } else if (raw && typeof raw === "object") {
    const j = raw as { sdl?: string; queries?: string[]; mutations?: string[] };
    if (j.sdl) return extractOperations(j.sdl);
    for (const q of j.queries ?? []) push(String(q), "query");
    for (const m of j.mutations ?? []) push(String(m), "mutation");
    // graphql_deep.json mutations: { name, args }[]
    const arrs = raw as { mutations?: { name?: string }[]; queries?: { name?: string }[] };
    for (const m of arrs.mutations ?? []) if (m.name) push(m.name, "mutation");
    for (const q of arrs.queries ?? []) if (q.name) push(q.name, "query");
  }
  return out;
};

export const probeGraphqlAuthz = async (input: GraphqlAuthzInput): Promise<GraphqlAuthzResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const raw = await readJsonIf(input.schemaFile);
  const fileText = typeof raw === "undefined" ? await readFile(input.schemaFile, "utf8").catch(() => "") : "";
  const ops = extractOperations(raw ?? fileText).slice(0, input.maxFields ?? 40);
  if (ops.length === 0) throw new Error("no operations extracted from schema file");

  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, headers: input.headers };
  const anonymous: GraphqlAuthzResult["anonymous"] = [];
  const lowPriv: GraphqlAuthzResult["lowPriv"] = [];

  const call = async (op: { name: string; kind: "query" | "mutation" }, authed: boolean): Promise<{ status: number; body: string }> => {
    const query = op.kind === "mutation"
      ? `mutation { ${op.name} }`
      : `query { ${op.name} }`;
    const headers = authed && input.token
      ? { ...input.headers, authorization: `Bearer ${input.token}` }
      : { ...input.headers };
    const r = await fetchUrl(input.endpoint, { ...opts, method: "POST", headers, body: JSON.stringify({ query }) });
    return { status: r.status, body: r.body };
  };

  for (const op of ops) {
    // Anonymous pass — mutations are called with a minimal (empty-args) shape;
    // many servers reject with a VALIDATION error (field required) which is
    // fine: the signal is AUTH errors vs validation/data errors.
    const r = await call(op, false);
    const authDenied = /must be authenticated|not authenticated|unauthor|forbidden|permission/i.test(r.body);
    const dataLeak = !authDenied && r.status < 300 && /"data"\s*:/.test(r.body) && !/"errors"\s*:/.test(r.body);
    anonymous.push({ field: op.name, kind: op.kind, status: r.status, errors: r.body.slice(0, 120), dataLeak });
    if (input.token) {
      const r2 = await call(op, true);
      const dataLeak2 = r2.status < 300 && /"data"\s*:/.test(r2.body) && !/"errors"\s*:/.test(r2.body);
      lowPriv.push({ field: op.name, kind: op.kind, status: r2.status, dataLeak: dataLeak2 });
    }
  }

  const unauthed = anonymous.filter((a) => a.dataLeak).map((a) => `${a.kind}:${a.field}`);
  const bodyStr = JSON.stringify({ probed: ops.length, anonymous, lowPriv, unauthed }, null, 2);
  const path = join(input.outputRoot, "graphql_authz.json");
  await writeFile(path, bodyStr, "utf8");
  return { probed: ops.length, anonymous, lowPriv, unauthed, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
