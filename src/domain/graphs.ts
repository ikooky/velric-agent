import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

/** Dual-graph persistence (velric platform layer, deterministic file-based
 *  port): the asset graph is a global shared truth store (root_domain →
 *  subdomain → ip → service → endpoint, deduped by computed keys); the
 *  exploration graph is per-run lineage (goal → intent → fact → finding,
 *  connected by spawns/derived_from/yields/proves edges). Anchors link
 *  exploration nodes to the assets they touched. */

// ---------------- asset graph ----------------

export type AssetType = "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint";

export interface AssetNode {
  readonly key: string;
  readonly type: AssetType;
  readonly value: string;
  parent?: string;
  taskTag?: string;
  readonly firstSeen: string;
  meta?: Record<string, unknown>;
}

export interface AssetGraph {
  assets: Record<string, AssetNode>;
}

const assetKey = (type: AssetType, value: string): string =>
  `${type}:${value.toLowerCase().replace(/\/+$/, "")}`;

export class AssetStore {
  private graph: AssetGraph = { assets: {} };
  private readonly file: string;

  constructor(root: string) { this.file = join(root, "asset_graph.json"); }

  async load(): Promise<void> {
    try { this.graph = JSON.parse(await readFile(this.file, "utf8")) as AssetGraph; }
    catch { this.graph = { assets: {} }; }
  }

  async save(): Promise<void> {
    await mkdir(join(this.file, ".."), { recursive: true });
    await writeFile(this.file, JSON.stringify(this.graph, null, 2));
  }

  upsert(input: { type: AssetType; value: string; parent?: string; taskTag?: string; meta?: Record<string, unknown> }): AssetNode {
    const key = assetKey(input.type, input.value);
    const existing = this.graph.assets[key];
    if (existing) {
      if (input.meta) existing.meta = { ...(existing.meta ?? {}), ...input.meta };
      if (input.taskTag && existing.taskTag !== input.taskTag) existing.taskTag = input.taskTag;
      return existing;
    }
    const node: AssetNode = {
      key, type: input.type, value: input.value, parent: input.parent,
      taskTag: input.taskTag, firstSeen: new Date().toISOString(), meta: input.meta,
    };
    this.graph.assets[key] = node;
    return node;
  }

  /** Host-chain normalization: a URL yields service+endpoint and is linked
   *  to its host domain chain (velric linkHostAssets). */
  upsertUrl(rawUrl: string, taskTag?: string): { service: AssetNode; endpoint: AssetNode } {
    const u = new URL(rawUrl);
    const host = u.hostname.toLowerCase();
    const service = this.upsert({ type: "service", value: `${u.protocol}//${host}${u.port ? ":" + u.port : ""}`, taskTag });
    const endpoint = this.upsert({ type: "endpoint", value: `${service.value}${u.pathname}`, parent: service.key, taskTag, meta: { method: u.searchParams.size } });
    if (u.searchParams.size > 0) endpoint.meta = { ...(endpoint.meta ?? {}), queryParams: [...u.searchParams.keys()] };
    // host chain: subdomain (if dotted) → root domain
    const parts = host.split(".").filter(Boolean);
    if (parts.length >= 2) {
      const root = parts.slice(-2).join(".");
      const rootNode = this.upsert({ type: "root_domain", value: root, taskTag });
      let parentKey = rootNode.key;
      if (parts.length > 2) {
        const sub = this.upsert({ type: "subdomain", value: host, parent: parentKey, taskTag });
        parentKey = sub.key;
      }
      // service anchored under host chain
      if (!service.parent) service.parent = parentKey;
    }
    return { service, endpoint };
  }

  queryByType(type: AssetType): AssetNode[] {
    return Object.values(this.graph.assets).filter((a) => a.type === type);
  }

  countsByType(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const a of Object.values(this.graph.assets)) out[a.type] = (out[a.type] ?? 0) + 1;
    return out;
  }
}

// ---------------- exploration graph ----------------

export type NodeKind = "goal" | "intent" | "fact" | "finding" | "hint";
export type NodeState = "open" | "met" | "dead" | "pending";

export interface ExpNode {
  id: string;
  kind: NodeKind;
  summary: string;
  state: NodeState;
  payload?: Record<string, unknown>;
  ts: string;
}

export interface ExpEdge {
  from: string; // parent/upstream
  rel: "spawns" | "derived_from" | "yields" | "proves";
  to: string; // child/downstream
}

export interface Anchor {
  nodeId: string;
  assetKey: string;
}

export class ExplorationGraph {
  private nodes = new Map<string, ExpNode>();
  private edges: ExpEdge[] = [];
  private anchors: Anchor[] = [];
  private counter = 0;
  private readonly file: string;

  constructor(root: string) { this.file = join(root, "exploration_graph.json"); }

  async load(): Promise<void> {
    try {
      const raw = JSON.parse(await readFile(this.file, "utf8")) as { nodes: ExpNode[]; edges: ExpEdge[]; anchors: Anchor[] };
      this.nodes = new Map(raw.nodes.map((n) => [n.id, n]));
      this.edges = raw.edges ?? [];
      this.anchors = raw.anchors ?? [];
      this.counter = raw.nodes.length;
    } catch { /* fresh */ }
  }

  async save(): Promise<void> {
    await mkdir(join(this.file, ".."), { recursive: true });
    await writeFile(this.file, JSON.stringify({ nodes: [...this.nodes.values()], edges: this.edges, anchors: this.anchors }, null, 2));
  }

  addNode(kind: NodeKind, summary: string, payload?: Record<string, unknown>): ExpNode {
    const id = `n${++this.counter}`;
    const node: ExpNode = { id, kind, summary, state: kind === "goal" ? "open" : "pending", payload, ts: new Date().toISOString() };
    this.nodes.set(id, node);
    return node;
  }

  addEdge(from: string, rel: ExpEdge["rel"], to: string): void {
    if (!this.edges.some((e) => e.from === from && e.rel === rel && e.to === to)) this.edges.push({ from, rel, to });
  }

  anchor(nodeId: string, assetKey: string): void {
    if (!this.anchors.some((a) => a.nodeId === nodeId && a.assetKey === assetKey)) this.anchors.push({ nodeId, assetKey });
  }

  setState(id: string, state: NodeState): void {
    const n = this.nodes.get(id);
    if (n) n.state = state;
  }

  /** Lineage: upstream parents and downstream yields of a node. */
  lineage(id: string): { parents: string[]; yields: string[] } {
    return {
      parents: this.edges.filter((e) => e.to === id).map((e) => e.from),
      yields: this.edges.filter((e) => e.from === id && (e.rel === "yields" || e.rel === "proves")).map((e) => e.to),
    };
  }

  /** Which assets has an exploration direction touched (anchor-driven). */
  assetsOf(nodeId: string): string[] {
    return this.anchors.filter((a) => a.assetKey && isDownstream(this, nodeId, a.nodeId)).map((a) => a.assetKey);
  }

  overview(): { goals: number; intents: number; facts: number; findings: number; hints: number; anchors: number } {
    const c = (k: NodeKind): number => [...this.nodes.values()].filter((n) => n.kind === k).length;
    return { goals: c("goal"), intents: c("intent"), facts: c("fact"), findings: c("finding"), hints: c("hint"), anchors: this.anchors.length };
  }
}

const isDownstream = (g: ExplorationGraph, ancestor: string, node: string, depth = 0): boolean => {
  if (ancestor === node) return true;
  if (depth > 8) return false;
  return g.edgesSnapshot().some((e) => e.from === ancestor && isDownstream(g, e.to, node, depth + 1));
};

// expose edges for traversal helpers
declare module "./graphs.js" {
  interface ExplorationGraph { edgesSnapshot(): ExpEdge[]; }
}
 ExplorationGraph.prototype.edgesSnapshot = function (this: ExplorationGraph): ExpEdge[] { return this["edges"]; } as never;

// ---------------- evidence store ----------------

export interface EvidenceBlob {
  readonly hash: string;
  readonly bytes: number;
  readonly storedAt: string;
  readonly tag?: string;
}

export class EvidenceStore {
  private readonly root: string;
  private index: Record<string, EvidenceBlob> = {};

  constructor(root: string) {
    this.root = root;
  }

  async load(): Promise<void> {
    try { this.index = JSON.parse(await readFile(join(this.root, "evidence_index.json"), "utf8")); }
    catch { this.index = {}; }
  }

  async save(): Promise<void> {
    await mkdir(this.root, { recursive: true });
    await writeFile(join(this.root, "evidence_index.json"), JSON.stringify(this.index, null, 2));
  }

  /** Store raw bytes, sha256-addressed, deduped across findings. */
  async put(data: Buffer, tag?: string): Promise<EvidenceBlob> {
    const hash = createHash("sha256").update(data).digest("hex");
    const existing = this.index[hash];
    if (existing) return existing;
    const dir = join(this.root, "blobs", hash.slice(0, 2));
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, hash + ".bin"), data);
    const blob: EvidenceBlob = { hash, bytes: data.length, storedAt: new Date().toISOString(), tag };
    this.index[hash] = blob;
    return blob;
  }

  async get(hash: string): Promise<Buffer | null> {
    try { return await readFile(join(this.root, "blobs", hash.slice(0, 2), hash + ".bin")); }
    catch { return null; }
  }

  entries(): EvidenceBlob[] { return Object.values(this.index); }
}
