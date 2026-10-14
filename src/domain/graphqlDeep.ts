import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { buildClientSchema, printSchema, parse, getIntrospectionQuery } from "graphql";

/** GraphQL deep introspection: full query (then minimal fallback for
 *  WAF-blocked sites), schema parse into the complete type/field/mutation
 *  surface, and optional diff against a previous schema file. */

export interface GraphqlDeepInput {
  readonly endpoint: string;
  readonly outputRoot: string;
  /** Previous schema file (graphql_schema.txt) to diff against. */
  readonly previousSchemaFile?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface GraphqlDeepResult {
  readonly endpoint: string;
  readonly introspected: boolean;
  readonly method: "full" | "minimal" | null;
  readonly typeCount: number;
  readonly queryCount: number;
  readonly mutationCount: number;
  readonly subscriptionCount: number;
  readonly diff: { added: string[]; removed: string[] } | null;
  readonly artifacts: { path: string; bytes: number }[];
}

const MINIMAL_QUERY = "{ __schema { types { name } } }";

const post = async (endpoint: string, query: string, opts: { headers?: Record<string, string>; proxy?: string; timeoutMs?: number }): Promise<{ status: number; body: string }> => {
  const r = await fetchUrl(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json", ...(opts.headers ?? {}) },
    body: JSON.stringify({ query }),
    proxy: opts.proxy,
    timeoutMs: opts.timeoutMs ?? 15000,
  });
  return { status: r.status, body: r.body };
};

export const probeGraphqlDeep = async (input: GraphqlDeepInput): Promise<GraphqlDeepResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { headers: input.headers, proxy: input.proxy, timeoutMs: input.timeoutMs };

  let introspected = false;
  let method: GraphqlDeepResult["method"] = null;
  let sdl = "";
  let typeCount = 0;
  let queryCount = 0;
  let mutationCount = 0;
  let subscriptionCount = 0;

  // Ladder: full introspection → minimal (WAFs often block the full query size).
  const full = await post(input.endpoint, getIntrospectionQuery(), opts);
  let data: unknown = null;
  if (full.status === 200) {
    try {
      const j = JSON.parse(full.body) as { data?: unknown; errors?: unknown };
      if (j.data && !j.errors) { data = j.data; method = "full"; }
    } catch { /* not json */ }
  }
  if (data === null) {
    const mini = await post(input.endpoint, MINIMAL_QUERY, opts);
    if (mini.status === 200) {
      try {
        const j = JSON.parse(mini.body) as { data?: unknown; errors?: unknown };
        if (j.data && !j.errors) { data = j.data; method = "minimal"; }
      } catch { /* not json */ }
    }
  }

  if (data !== null) {
    introspected = true;
    try {
      const schema = buildClientSchema(data as never);
      sdl = printSchema(schema);
      const ast = parse(sdl);
      const typeDefs = ast.definitions.filter((d) => d.kind === "ObjectTypeDefinition").map((d) => (d as { name: { value: string } }).name.value);
      const fieldsOf = (t: string): number => {
        const def = ast.definitions.find((d) => d.kind === "ObjectTypeDefinition" && (d as { name: { value: string } }).name.value === t) as { fields?: unknown[] } | undefined;
        return def?.fields?.length ?? 0;
      };
      queryCount = fieldsOf("Query");
      mutationCount = fieldsOf("Mutation");
      subscriptionCount = fieldsOf("Subscription");
      // exclude built-ins for a meaningful count
      const builtins = new Set(["Query", "Mutation", "Subscription", "String", "Int", "Float", "Boolean", "ID"]);
      typeCount = typeDefs.filter((t) => !builtins.has(t)).length;
    } catch {
      // schema build failed on odd servers — keep raw SDL empty, counts zero
    }
  }

  // Diff against previous run's schema.
  let diff: GraphqlDeepResult["diff"] = null;
  if (input.previousSchemaFile && sdl) {
    try {
      const { readFile } = await import("node:fs/promises");
      const prev = await readFile(input.previousSchemaFile, "utf8");
      const prevLines = new Set(prev.split("\n"));
      const nowLines = new Set(sdl.split("\n"));
      const added = [...nowLines].filter((l) => !prevLines.has(l) && l.trim().length > 0).slice(0, 200);
      const removed = [...prevLines].filter((l) => !nowLines.has(l) && l.trim().length > 0).slice(0, 200);
      diff = { added, removed };
    } catch { /* no previous file */ }
  }

  const schemaPath = join(input.outputRoot, "graphql_schema.txt");
  const result: GraphqlDeepResult = {
    endpoint: input.endpoint,
    introspected, method,
    typeCount, queryCount, mutationCount, subscriptionCount,
    diff,
    artifacts: sdl ? [{ path: schemaPath, bytes: Buffer.byteLength(sdl) }] : [],
  };
  const body = JSON.stringify({ ...result, sdl: sdl.slice(0, 20000) }, null, 2);
  await writeFile(join(input.outputRoot, "graphql_deep.json"), body);
  if (sdl) await writeFile(schemaPath, sdl);
  return result;
};
