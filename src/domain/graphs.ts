import { createHash } from "node:crypto";
import { assertHash, putBlob, readBlob, readJson, writeJson, withRootLock } from "../core/storage.js";

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
  taskTags?: string[];
  readonly firstSeen: string;
  meta?: Record<string, unknown>;
}

export interface AssetGraph {
  version?: number;
  assets: Record<string, AssetNode>;
}

const assetKey = (type: AssetType, value: string): string =>
  `${type}:${value.toLowerCase().replace(/\/+$/, "")}`;

export class AssetStore {
  private graph: AssetGraph = { assets: {} };
  constructor(private readonly root: string) {}
  private async read(): Promise<AssetGraph> {
    return readJson(this.root,"asset_graph.json",()=>({assets:{},version:0}),value=>{
      const g=value as AssetGraph;
      return !!g && !!g.assets && typeof g.assets==="object" && !Array.isArray(g.assets) &&
        (g.version===undefined || Number.isSafeInteger(g.version) && g.version>=0) &&
        Object.entries(g.assets).every(([key,a])=>a?.key===key && typeof a.value==="string" &&
          ["root_domain","subdomain","ip","service","app","endpoint"].includes(a.type) && typeof a.firstSeen==="string" &&
          (a.taskTags===undefined || Array.isArray(a.taskTags) && a.taskTags.every(t=>typeof t==="string")));
    });
  }
  async load(): Promise<void> { this.graph=await this.read(); }
  async save(): Promise<void> {
    await withRootLock(this.root,async()=>{
      const disk=await this.read();
      if((disk.version??0)!==(this.graph.version??0))throw Object.assign(new Error("asset graph version conflict"),{code:"version_conflict"});
      const next={...this.graph,version:(disk.version??0)+1};
      await writeJson(this.root,"asset_graph.json",next); this.graph=next;
    });
  }

  /** Read-only snapshot for retrieval layers (scan platform list/count). */
  all(): AssetNode[] { return Object.values(this.graph.assets); }

  upsert(input: { type: AssetType; value: string; parent?: string; taskTag?: string; meta?: Record<string, unknown> }): AssetNode {
    const key = assetKey(input.type, input.value);
    const existing = this.graph.assets[key];
    if (existing) {
      if (input.meta) existing.meta = { ...(existing.meta ?? {}), ...input.meta };
      const tags=[...new Set([...(existing.taskTags??[]),...(existing.taskTag?[existing.taskTag]:[]),...(input.taskTag?[input.taskTag]:[])])];
      if(tags.length)existing.taskTags=tags;
      if(!existing.taskTag && input.taskTag)existing.taskTag=input.taskTag;
      return existing;
    }
    const node: AssetNode = {
      key, type: input.type, value: input.value, parent: input.parent,
      taskTag: input.taskTag, taskTags: input.taskTag ? [input.taskTag] : [], firstSeen: new Date().toISOString(), meta: input.meta,
    };
    this.graph.assets[key] = node;
    return node;
  }

  /** Host-chain normalization: a URL yields service+endpoint and is linked
   *  to its host domain chain (velric linkHostAssets). */
  upsertUrl(rawUrl: string, taskTag?: string): { service: AssetNode; endpoint: AssetNode } {
    // Dirty URL inputs must not abort the whole asset-chain write.
    let u: URL;
    try { u = new URL(rawUrl); } catch { throw new Error(`invalid url: ${JSON.stringify(rawUrl.slice(0, 60))}`); }
    const host = u.hostname.toLowerCase();
    const service = this.upsert({ type: "service", value: `${u.protocol}//${host}${u.port ? ":" + u.port : ""}`, taskTag });
    const endpoint = this.upsert({ type: "endpoint", value: `${service.value}${u.pathname}`, parent: service.key, taskTag });
    if (u.searchParams.size > 0) endpoint.meta = { ...(endpoint.meta ?? {}), queryParamCount: u.searchParams.size, queryParams: [...u.searchParams.keys()] };
    // host chain: subdomain (if dotted) → root domain
    const parts = host.split(".").filter(Boolean);
    if (parts.length >= 2) {
      // Common multi-label public suffixes where last-2-labels would give a
      // bare suffix (api.example.co.uk -> co.uk). Small built-in list; the
      // full PSL is overkill for recon tagging.
      const MULTI_SUFFIX = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "com.cn", "com.tw", "com.hk", "co.jp", "co.kr", "co.in", "co.za", "com.sg", "com.my"]);
      const last2 = parts.slice(-2).join(".");
      const last3 = parts.slice(-3).join(".");
      const root = parts.length >= 3 && MULTI_SUFFIX.has(last2) ? last3 : last2;
      // A host that IS itself a public suffix (bare co.uk) must not become a
      // root_domain node — only register real registrable domains. Every
      // other host (including a bare two-label registrable domain) gets one.
      let parentKey: string | undefined;
      if (!MULTI_SUFFIX.has(host)) {
        const rootNode = this.upsert({ type: "root_domain", value: root, taskTag });
        parentKey = rootNode.key;
        // Only a strict sub-host (host !== root) becomes a subdomain node — the
        // registrable domain itself (example.co.uk, host === root) must not
        // be duplicated into the subdomain tier.
        if (parts.length > 2 && host !== root) {
          const sub = this.upsert({ type: "subdomain", value: host, parent: parentKey, taskTag });
          parentKey = sub.key;
        }
      }
      // service anchored under host chain
      if (!service.parent && parentKey) service.parent = parentKey;
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
  version?: number;
  touchVersion?: number;
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
  private version = 0;
  constructor(private readonly root: string) {}
  private async read(): Promise<{nodes:ExpNode[];edges:ExpEdge[];anchors:Anchor[];version?:number;counter?:number}> {
    return readJson(this.root,"exploration_graph.json",()=>({nodes:[],edges:[],anchors:[],version:0}),value=>{
      const g=value as {nodes:ExpNode[];edges:ExpEdge[];anchors:Anchor[];version?:number;counter?:number};
      if(!g || !Array.isArray(g.nodes) || !Array.isArray(g.edges) || !Array.isArray(g.anchors) ||
        g.version!==undefined && (!Number.isSafeInteger(g.version)||g.version<0))return false;
      const ids=new Set(g.nodes.map(n=>n?.id));
      return ids.size===g.nodes.length && g.nodes.every(n=>n && typeof n.id==="string" && typeof n.summary==="string" &&
        ["goal","intent","fact","finding","hint"].includes(n.kind) && ["open","met","dead","pending"].includes(n.state) && typeof n.ts==="string") &&
        g.edges.every(e=>ids.has(e.from)&&ids.has(e.to)&&["spawns","derived_from","yields","proves"].includes(e.rel)) &&
        g.anchors.every(a=>ids.has(a.nodeId)&&typeof a.assetKey==="string");
    });
  }
  async load(): Promise<void> {
    const raw=await this.read(); this.nodes=new Map(raw.nodes.map(n=>[n.id,n])); this.edges=raw.edges;this.anchors=raw.anchors;
    this.version=raw.version??0;
    this.counter=Math.max(raw.counter??0,...raw.nodes.map(n=>Number(n.id.replace(/^n/,""))||0),0);
  }
  async save(): Promise<void> {
    await withRootLock(this.root,async()=>{
      const disk=await this.read();if((disk.version??0)!==this.version)throw Object.assign(new Error("exploration graph version conflict"),{code:"version_conflict"});
      const next=this.version+1;
      await writeJson(this.root,"exploration_graph.json",{nodes:[...this.nodes.values()],edges:this.edges,anchors:this.anchors,counter:this.counter,version:next});this.version=next;
    });
  }

  addNode(kind: NodeKind, summary: string, payload?: Record<string, unknown>): ExpNode {
    const id = `n${++this.counter}`;
    const node: ExpNode = { id, kind, summary, state: kind === "goal" ? "open" : "pending", payload, version:0, touchVersion:0, ts: new Date().toISOString() };
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
    if (n && n.state!==state) { n.state=state; n.version=(n.version??0)+1; }
  }

  touch(id: string): void { const n=this.nodes.get(id); if(n)n.touchVersion=(n.touchVersion??0)+1; }

  /** Lineage: upstream parents and downstream yields of a node. */
  lineage(id: string): { parents: string[]; yields: string[] } {
    this.touch(id);
    return {
      parents: this.edges.filter((e) => e.to === id).map((e) => e.from),
      yields: this.edges.filter((e) => e.from === id && (e.rel === "yields" || e.rel === "proves")).map((e) => e.to),
    };
  }

  /** Which assets has an exploration direction touched (anchor-driven). */
  assetsOf(nodeId: string): string[] {
    this.touch(nodeId);
    return [...new Set(this.anchors.filter((a) => a.assetKey && isDownstream(this, nodeId, a.nodeId)).map((a) => a.assetKey))];
  }

  overview(): { goals: number; intents: number; facts: number; findings: number; hints: number; anchors: number } {
    const c = (k: NodeKind): number => [...this.nodes.values()].filter((n) => n.kind === k).length;
    return { goals: c("goal"), intents: c("intent"), facts: c("fact"), findings: c("finding"), hints: c("hint"), anchors: this.anchors.length };
  }

  /** Read-only view of the edge list for traversal helpers. */
  edgesSnapshot(): ExpEdge[] {
    return this.edges;
  }
}

const isDownstream = (g: ExplorationGraph, ancestor: string, node: string, depth = 0): boolean => {
  if (ancestor === node) return true;
  if (depth > 8) return false;
  return g.edgesSnapshot().some((e) => e.from === ancestor && isDownstream(g, e.to, node, depth + 1));
};

// (edgesSnapshot is now a real public method on the class — the previous
//  prototype monkey-patch reached into private state via this["edges"].)

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
    this.index = await readJson(this.root, "evidence_index.json", () => ({}), (value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return false;
      return Object.entries(value).every(([hash, blob]) => /^[a-f0-9]{64}$/.test(hash) && blob &&
        blob.hash === hash && Number.isSafeInteger(blob.bytes) && blob.bytes >= 0 && typeof blob.storedAt === "string");
    });
  }

  /** put commits its index in the same transaction; save refreshes a detached view. */
  async save(): Promise<void> { await withRootLock(this.root, () => this.load()); }

  async put(data: Buffer, tag?: string): Promise<EvidenceBlob> {
    return withRootLock(this.root, async () => {
      await this.load();
      const hash = createHash("sha256").update(data).digest("hex");
      const previous = this.index[hash];
      const bytes = await readBlob(this.root, hash);
      if (previous && (!bytes || bytes.length !== previous.bytes)) {
        throw Object.assign(new Error("indexed evidence length mismatch or missing blob"), {code:"evidence_integrity"});
      }
      await putBlob(this.root, data);
      const blob: EvidenceBlob = previous ?? { hash, bytes: data.length, storedAt: new Date().toISOString(), tag };
      this.index[hash] = blob;
      await writeJson(this.root, "evidence_index.json", this.index);
      return blob;
    });
  }

  async get(hash: string): Promise<Buffer | null> {
    assertHash(hash);
    await this.load();
    const data = await readBlob(this.root, hash);
    const entry = this.index[hash];
    if (entry && (!data || data.length !== entry.bytes)) {
      throw Object.assign(new Error("indexed evidence length mismatch or missing blob"), {code:"evidence_integrity"});
    }
    return data;
  }

  entries(): EvidenceBlob[] { return Object.values(this.index); }
}
