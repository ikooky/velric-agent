import { readFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { request as undiciRequest } from "undici";
import {
  astFromValue,
  buildSchema,
  GraphQLEnumType,
  GraphQLInterfaceType,
  GraphQLList,
  GraphQLNonNull,
  GraphQLObjectType,
  GraphQLScalarType,
  GraphQLSchema,
  GraphQLUnionType,
  parse,
  print,
  validate,
  type GraphQLField,
  type GraphQLType,
} from "graphql";
import { principalHash, stripCredentials } from "../core/credentials.js";
import { executionRunId, recordReceipt } from "../core/execution.js";
import { httpDispatcher } from "../adapters/http.js";

/** GraphQL field-level authorization: build schema-valid AST operations from
 *  the introspected SDL (graphql buildSchema/parse/validate — never regex
 *  string surgery), fire each root query anonymously and with a low-priv
 *  token, and judge disclosure on the DATA the anonymous response actually
 *  carries. Mutations are state-changing: skipped by default and reported. */

export interface GraphqlAuthzInput {
  readonly endpoint: string;
  /** SDL text file, or graphql_deep.json carrying { sdl }. */
  readonly schemaFile: string;
  readonly outputRoot: string;
  /** low-priv token (Bearer). Anonymous pass always runs. */
  readonly token?: string;
  readonly headers?: Record<string, string>;
  /** Root-argument values keyed "<kind>:<field>" → { argName: value }. A
   *  field whose required argument has no value is skipped, not guessed. */
  readonly arguments?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxFields?: number;
}

export interface GraphqlAuthzResult {
  readonly probed: number;
  readonly anonymous: { field: string; kind: "query" | "mutation"; status: number; errors?: string; dataLeak: boolean }[];
  readonly lowPriv: { field: string; kind: "query" | "mutation"; status: number; dataLeak: boolean }[];
  readonly unauthed: string[];
  /** Root operations NOT fired, with the reason (mutations by default;
   *  unsatisfiable required arguments; unrepresentable selections). */
  readonly skipped: { field: string; reason: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const sha256 = (v: string): string => createHash("sha256").update(v).digest("hex");

const loadSchema = async (schemaFile: string): Promise<GraphQLSchema> => {
  const text = await readFile(schemaFile, "utf8");
  let sdl: string | undefined;
  try {
    const raw: unknown = JSON.parse(text);
    if (typeof raw === "string") sdl = raw;
    else if (raw && typeof raw === "object" && typeof (raw as { sdl?: unknown }).sdl === "string") sdl = (raw as { sdl: string }).sdl;
  } catch {
    sdl = text; // plain SDL dump
  }
  if (!sdl || !/type\s|schema\s|extend\s/.test(sdl)) throw new Error("schema file must contain SDL text (or json with an sdl field)");
  return buildSchema(sdl);
};

/** Strip NonNull/List wrappers down to the named type. */
const bare = (type: GraphQLType): GraphQLType => (type instanceof GraphQLNonNull || type instanceof GraphQLList ? bare(type.ofType) : type);

/** Nested field args cannot be satisfied from the root argument map — a
 *  nested required argument without a default disqualifies the field. */
const argsSatisfiable = (field: GraphQLField<unknown, unknown>): boolean =>
  field.args.every((a) => !(a.type instanceof GraphQLNonNull) || a.defaultValue !== undefined);

const MAX_SELECT_DEPTH = 2;
const MAX_FIELDS_PER_TYPE = 8;

/** Selection set for an object/interface type, or null when nothing valid
 *  can be selected (every candidate field is an object past the depth cap
 *  or carries unsatisfiable required arguments). */
const objectSelection = (type: GraphQLObjectType | GraphQLInterfaceType, depth: number): string | null => {
  if (depth > MAX_SELECT_DEPTH) return null;
  const parts: string[] = [];
  for (const [name, field] of Object.entries(type.getFields())) {
    if (name.startsWith("__") || parts.length >= MAX_FIELDS_PER_TYPE) continue;
    if (!argsSatisfiable(field)) continue;
    const sub = selectionFor(field.type, depth);
    if (sub === null) continue;
    parts.push(name + sub);
  }
  return parts.length > 0 ? ` { ${parts.join(" ")} }` : null;
};

/** Sub-selection text appended after a field name; "" = none required
 *  (scalar/enum), null = no valid selection exists (skip the field). */
const selectionFor = (type: GraphQLType, depth: number): string | null => {
  const base = bare(type);
  if (base instanceof GraphQLScalarType || base instanceof GraphQLEnumType) return "";
  if (base instanceof GraphQLObjectType || base instanceof GraphQLInterfaceType) return objectSelection(base, depth + 1);
  if (base instanceof GraphQLUnionType) {
    const frags: string[] = [];
    for (const member of base.getTypes()) {
      const sel = objectSelection(member, depth + 1);
      if (sel) frags.push(`... on ${member.name} ${sel}`);
    }
    return frags.length > 0 ? ` { ${frags.join(" ")} }` : null;
  }
  return null;
};

type Built = { query: string } | { skip: string };

/** Build ONE schema-valid root operation: required arguments must carry a
 *  value from the input argument map, values render through graphql's own
 *  astFromValue/print, and the result is parse+validate-checked before use. */
const buildOperation = (
  schema: GraphQLSchema,
  kind: "query" | "mutation",
  name: string,
  argsMap: Readonly<Record<string, unknown>> | undefined,
): Built => {
  const rootType = kind === "query" ? schema.getQueryType() : schema.getMutationType();
  const field = rootType?.getFields()[name];
  if (!field) return { skip: `field ${name} missing from the ${kind} root type` };
  const argParts: string[] = [];
  for (const arg of field.args) {
    const value = argsMap?.[arg.name];
    if (value === undefined) {
      if (arg.type instanceof GraphQLNonNull && arg.defaultValue === undefined) return { skip: `required argument '${arg.name}' has no value` };
      continue; // optional and absent: omit
    }
    const literal = astFromValue(value, arg.type);
    if (!literal) return { skip: `argument '${arg.name}' value cannot be represented as ${String(arg.type)}` };
    argParts.push(`${arg.name}: ${print(literal)}`);
  }
  const selection = selectionFor(field.type, 0);
  if (selection === null) return { skip: `no representable selection set for ${String(field.type)}` };
  const op = `${kind} { ${name}${argParts.length > 0 ? `(${argParts.join(", ")})` : ""}${selection} }`;
  const errors = validate(schema, parse(op));
  if (errors.length > 0) return { skip: `generated operation failed validation: ${errors[0]?.message ?? "unknown"}` };
  return { query: op };
};

/** POST {query} as a JSON body. undici request() keeps string bodies intact
 *  end-to-end (fetch()-based transports re-encode bodies through streams),
 *  so wire observers and recorders see the exact JSON that was sent. */
const postQuery = async (
  url: string,
  headers: Record<string, string>,
  body: string,
  opts: { proxy?: string; timeoutMs?: number },
): Promise<{ status: number; body: string }> => {
  const dispatcher = httpDispatcher(opts.proxy);
  try {
    const r = await undiciRequest(url, {
      method: "POST",
      headers,
      body,
      ...(dispatcher ? { dispatcher } : {}),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 8000),
    });
    return { status: r.statusCode, body: await r.body.text() };
  } catch {
    return { status: 0, body: "" };
  }
};

/** Disclosure verdict per the response the endpoint actually returned:
 *  partial data (data present AND errors present) is preserved — a non-null
 *  value under data[field] is a leak even when sibling errors complain. */
const interpret = (field: string, status: number, body: string): { errors?: string; dataLeak: boolean } => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { errors: body.slice(0, 120), dataLeak: false };
  }
  const data = parsed && typeof parsed === "object" ? (parsed as { data?: unknown }).data : undefined;
  const value = data && typeof data === "object" ? (data as Record<string, unknown>)[field] : undefined;
  const errObj = parsed && typeof parsed === "object" ? (parsed as { errors?: unknown }).errors : undefined;
  const messages = Array.isArray(errObj)
    ? errObj.map((e) => (e && typeof e === "object" ? String((e as { message?: unknown }).message ?? "") : String(e))).filter(Boolean).join("; ").slice(0, 120)
    : undefined;
  const dataLeak = status >= 200 && status < 300 && value !== null && value !== undefined;
  return { ...(messages ? { errors: messages } : {}), dataLeak };
};

export const probeGraphqlAuthz = async (input: GraphqlAuthzInput): Promise<GraphqlAuthzResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const schema = await loadSchema(input.schemaFile);
  const maxFields = input.maxFields ?? 40;
  const queryType = schema.getQueryType();
  if (!queryType) throw new Error("schema has no Query root type");

  const anonymous: GraphqlAuthzResult["anonymous"] = [];
  const lowPriv: GraphqlAuthzResult["lowPriv"] = [];
  const skipped: GraphqlAuthzResult["skipped"] = [];
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };

  const fire = async (query: string, headers: Record<string, string>): Promise<{ status: number; body: string }> => {
    const r = await postQuery(input.endpoint, headers, JSON.stringify({ query }), opts);
    if (executionRunId() !== "unbound") {
      await recordReceipt({
        url: input.endpoint,
        method: "POST",
        status: r.status,
        requestHash: sha256(JSON.stringify({ url: input.endpoint, headers, body: query })),
        responseHash: sha256(r.body),
        principal: principalHash(headers),
        complete: r.status > 0,
      });
    }
    return r;
  };

  // Anonymous pass: the credential strippers in core/credentials remove every
  // identified carrier (cookie/authorization/api-key/CSRF shapes).
  const anonHeaders = { ...stripCredentials(input.headers), "content-type": "application/json" };
  const lowHeaders = input.token
    ? { ...stripCredentials(input.headers), "content-type": "application/json", authorization: `Bearer ${input.token}` }
    : undefined;

  let considered = 0;
  for (const [name] of Object.entries(queryType.getFields())) {
    if (name.startsWith("__")) continue;
    if (considered >= maxFields) break;
    considered++;
    const built = buildOperation(schema, "query", name, input.arguments?.[`query:${name}`]);
    if ("skip" in built) {
      skipped.push({ field: name, reason: built.skip });
      continue;
    }
    const r1 = await fire(built.query, anonHeaders);
    anonymous.push({ field: name, kind: "query", status: r1.status, ...interpret(name, r1.status, r1.body) });
    if (lowHeaders) {
      const r2 = await fire(built.query, lowHeaders);
      lowPriv.push({ field: name, kind: "query", status: r2.status, dataLeak: interpret(name, r2.status, r2.body).dataLeak });
    }
  }

  // Mutations change server state — never fired by default; each one is
  // reported in skipped[] so the operator can decide on an explicit policy.
  for (const [name] of Object.entries(schema.getMutationType()?.getFields() ?? {})) {
    if (name.startsWith("__")) continue;
    if (considered >= maxFields) break;
    considered++;
    skipped.push({ field: name, reason: "mutation: write operations are skipped by default (state-changing)" });
  }

  // Danger ranking: anonymous data disclosure is the finding; write-shaped
  // mutation names would be the escalation surface when explicitly enabled.
  const DANGER_RE = /^(?:delete|remove|drop|update|set|reset|create|add|insert|put|post|grant|assign|revoke|promote|disable|enable|impersonate|makeAdmin|updateRole)/i;
  const ranked = anonymous
    .filter((a) => a.dataLeak)
    .map((a) => ({ op: `${a.kind}:${a.field}`, danger: a.kind === "mutation" && DANGER_RE.test(a.field) ? "high" : a.kind === "mutation" ? "medium" : "info" }));
  const unauthed = ranked.map((r) => r.op);

  const bodyStr = JSON.stringify({ probed: considered, anonymous, lowPriv, skipped, unauthed, unauthedRanked: ranked }, null, 2);
  const path = join(input.outputRoot, "graphql_authz.json");
  await writeFile(path, bodyStr, "utf8");
  return { probed: considered, anonymous, lowPriv, unauthed, skipped, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] };
};
