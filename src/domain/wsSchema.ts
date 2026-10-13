import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** WebSocket message schema extraction: parse recorded JSON frames
 *  (runtime_api.json → wsFrames) into per-endpoint field tables — the
 *  interface documentation of a private protocol, derived from real traffic. */

export interface WsSchemaInput {
  /** runtime_api.json path. */
  readonly runtimeFile: string;
  readonly outputRoot: string;
}

export interface WsSchemaResult {
  readonly endpoints: number;
  readonly framesParsed: number;
  readonly schemas: {
    endpoint: string;
    dir: string;
    frames: number;
    fields: { path: string; types: string[]; sampleValues: string[] }[];
    sampleMessages: string[];
  }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const typeOf = (v: unknown): string => {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
};

/** Flatten a JSON message into dotted field paths with types + samples. */
const flatten = (v: unknown, prefix: string, out: Map<string, { types: Set<string>; samples: string[] }>): void => {
  if (v === null || typeof v !== "object") {
    const cur = out.get(prefix) ?? { types: new Set<string>(), samples: [] };
    cur.types.add(typeOf(v));
    if (cur.samples.length < 3) cur.samples.push(String(v).slice(0, 40));
    out.set(prefix, cur);
    return;
  }
  if (Array.isArray(v)) {
    const cur = out.get(prefix) ?? { types: new Set<string>(), samples: [] };
    cur.types.add("array");
    out.set(prefix, cur);
    for (const x of v.slice(0, 5)) flatten(x, `${prefix}[]`, out);
    return;
  }
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    flatten(val, prefix ? `${prefix}.${k}` : k, out);
  }
};

export const extractWsSchema = async (input: WsSchemaInput): Promise<WsSchemaResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  let frames: { url: string; dir: string; data: string }[] = [];
  try {
    const rt = JSON.parse(await readFile(input.runtimeFile, "utf8")) as { wsFrames?: { url: string; dir: string; data: string }[] };
    frames = rt.wsFrames ?? [];
  } catch {
    return { endpoints: 0, framesParsed: 0, schemas: [], artifacts: [] };
  }

  // Group frames by endpoint (url) — protocol shape usually differs per socket.
  const byEndpoint = new Map<string, { dir: string; data: string }[]>();
  for (const f of frames) {
    const list = byEndpoint.get(f.url) ?? [];
    list.push({ dir: f.dir, data: f.data });
    byEndpoint.set(f.url, list);
  }

  const schemas: WsSchemaResult["schemas"] = [];
  let parsed = 0;
  for (const [endpoint, list] of byEndpoint) {
    const fieldMap = new Map<string, { types: Set<string>; samples: string[] }>();
    const samples: string[] = [];
    for (const f of list) {
      let msg: unknown;
      try {
        msg = JSON.parse(f.data);
        parsed++;
      } catch {
        continue; // non-JSON protocol (protobuf/binary) — record raw samples only
      }
      if (samples.length < 3) samples.push(f.data.slice(0, 200));
      flatten(msg, "", fieldMap);
    }
    if (fieldMap.size === 0) continue;
    schemas.push({
      endpoint,
      dir: list[0]?.dir ?? "?",
      frames: list.length,
      fields: [...fieldMap.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([path, v]) => ({ path, types: [...v.types], sampleValues: v.samples })),
      sampleMessages: samples,
    });
  }

  const path = join(input.outputRoot, "ws_schema.json");
  const body = JSON.stringify({ endpoints: schemas.length, framesParsed: parsed, schemas }, null, 2);
  await writeFile(path, body);
  return { endpoints: schemas.length, framesParsed: parsed, schemas, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
