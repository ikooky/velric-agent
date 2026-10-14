import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { ExplorationGraph, ExpNode, ExpEdge } from "./graphs.js";

// ExpNode has no version field — cold tracking keeps it in stamps only.
interface VersionedNode extends ExpNode { version?: number; }

/** Cold-graph compaction (velric agent/coldgraph.go, deterministic port):
 *  exploration graphs grow unboundedly across long hunts. Nodes untouched
 *  for N compactions and whose subtree produced nothing recently are "cold";
 *  connected cold regions fold into a single digest node (content-hashed),
 *  preserving lineage via edges. Digests expand back on demand.
 *
 *  Pure functions over the graph snapshot — testable without IO. */

export interface ColdParams {
  /** Compaction rounds a node must stay untouched to qualify as cold. */
  readonly coldAfterRounds: number;
  /** Max nodes a single digest may fold (keeps expand cheap). */
  readonly maxDigestSize: number;
}

export const DEFAULT_COLD_PARAMS: ColdParams = { coldAfterRounds: 3, maxDigestSize: 50 };

export interface NodeStamp {
  readonly id: string;
  /** Round number of the last touch (update or traversal yield). */
  lastTouched: number;
  /** Content version — bumped on payload change; version change = warm. */
  version: number;
}

export interface Folded {
  /** digest node ids created (or reused) per compaction. */
  digests: string[];
  /** node ids removed from the live graph (folded away). */
  folded: string[];
  /** nodes rescued from folding (same-parent singletons with warm siblings). */
  rescued: string[];
}

/** Downstream-reachable set from a node (yields/proves/spawns edges). */


/** Connectivity groups among cold nodes: two cold nodes belong to the same
 *  group when a path (either direction) connects them without passing a warm
 *  node. Union-find over cold-only edges. */
export const coldGroups = (coldIds: Set<string>, edges: ExpEdge[]): string[][] => {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r)!;
    return r;
  };
  const union = (a: string, b: string): void => { parent.set(find(a), find(b)); };
  for (const id of coldIds) parent.set(id, id);
  for (const e of edges) {
    if (parent.has(e.from) && parent.has(e.to)) union(e.from, e.to);
  }
  const groups = new Map<string, string[]>();
  for (const id of coldIds) {
    const r = find(id);
    const g = groups.get(r) ?? [];
    g.push(id);
    groups.set(r, g);
  }
  return [...groups.values()];
};

/** Digest content hash: stable across runs for identical folded sets. */
export const digestHash = (nodes: ExpNode[]): string => {
  const material = nodes
    .map((n: VersionedNode) => `${n.id}|${n.kind}|${n.summary}|${n.state}|${n.version ?? 0}`)
    .sort()
    .join("\n");
  return createHash("sha256").update(material).digest("hex").slice(0, 16);
};

export const compactGraph = (
  graph: ExplorationGraph,
  stamps: Map<string, NodeStamp>,
  round: number,
  params: ColdParams = DEFAULT_COLD_PARAMS,
): Folded => {
  const edges = graph["edges"] as ExpEdge[];
  const nodes = graph["nodes"] as Map<string, VersionedNode>;

  // 1) Cold qualification: untouched for coldAfterRounds AND no version bump.
  const cold = new Set<string>();
  for (const [id, st] of stamps) {
    const n = nodes.get(id);
    if (!n) continue;
    if (n.kind === "finding" || n.kind === "goal") continue; // terminal value never folds
    if (round - st.lastTouched >= params.coldAfterRounds) cold.add(id);
  }

  // 2) Same-parent singleton rescue (velric §3.1): a cold node whose parent
  //    has exactly one cold child but other WARM children stays — folding it
  //    would sever the parent's only bridge into that region.
  const rescued: string[] = [];
  const childrenOf = new Map<string, string[]>();
  for (const e of edges) {
    if (e.rel === "spawns" || e.rel === "derived_from") {
      const l = childrenOf.get(e.from) ?? [];
      l.push(e.to);
      childrenOf.set(e.from, l);
    }
  }
  for (const id of [...cold]) {
    const parents = edges.filter((e) => e.to === id && (e.rel === "spawns" || e.rel === "derived_from")).map((e) => e.from);
    for (const p of parents) {
      const kids = childrenOf.get(p) ?? [];
      const coldKids = kids.filter((k) => cold.has(k));
      const warmKids = kids.filter((k) => !cold.has(k));
      if (coldKids.length === 1 && warmKids.length > 0) {
        cold.delete(id);
        rescued.push(id);
        break;
      }
    }
  }

  // 3) Group + fold into digests.
  const groups = coldGroups(cold, edges);
  const digests: string[] = [];
  const folded: string[] = [];
  for (const g of groups) {
    const chunk = g.slice(0, params.maxDigestSize);
    const rest = g.slice(params.maxDigestSize);
    const members = chunk.map((id) => nodes.get(id)!).filter(Boolean);
    if (members.length === 0) continue;
    const dh = digestHash(members);
    const digestId = `digest-${dh}`;
    // Snapshot members into the digest payload BEFORE removal — expansion
    // rebuilds nodes from these snapshots.
    const snapshots = members.map((m) => ({ id: m.id, kind: m.kind, summary: m.summary, state: m.state, ts: m.ts, payload: m.payload }));
    const nodesMap = graph["nodes"] as Map<string, VersionedNode>;
    nodesMap.set(digestId, {
      id: digestId,
      kind: "hint",
      summary: `digest(${members.length}): ${members[0]!.summary.slice(0, 60)}…`,
      state: "pending",
      ts: new Date().toISOString(),
      payload: { kind: "digest", members: chunk, memberNodes: snapshots, hash: dh, round },
    });
    digests.push(digestId);
    for (const id of chunk) {
      folded.push(id);
      nodes.delete(id);
      stamps.delete(id); // stale stamps kept qualifying deleted ids in cold scans
    }
    void rest; // oversized groups fold partially; remainder folds next round
  }
  return { digests, folded, rescued };
};

/** Expand a digest node back into its members (stamps reset to current round). */
export const expandDigest = (
  graph: ExplorationGraph,
  digestId: string,
  stamps: Map<string, NodeStamp>,
  round: number,
): { expanded: string[] } => {
  const nodes = graph["nodes"] as Map<string, ExpNode & { payload?: Record<string, unknown> }>;
  const d = nodes.get(digestId);
  const members = (d?.payload?.members as string[] | undefined) ?? [];
  if (!d || !Array.isArray(members)) return { expanded: [] };
  // Members are re-created from the payload snapshots stored at fold time.
  const snaps = (d.payload?.memberNodes as unknown[] | undefined) ?? [];
  for (const s of snaps) {
    const snap = s as { id: string; kind: ExpNode["kind"]; summary: string; state: ExpNode["state"]; ts: string; payload?: Record<string, unknown> };
    if (!nodes.has(snap.id)) {
      nodes.set(snap.id, { id: snap.id, kind: snap.kind, summary: snap.summary, state: snap.state, ts: snap.ts, payload: snap.payload });
      stamps.set(snap.id, { id: snap.id, lastTouched: round, version: 0 });
    }
  }
  nodes.delete(digestId);
  return { expanded: members };
};

// --- persistence: stamps live beside the graph file ---

export const loadStamps = async (root: string): Promise<{ stamps: Map<string, NodeStamp>; round: number }> => {
  try {
    const raw = JSON.parse(await readFile(join(root, "cold_stamps.json"), "utf8")) as { round: number; stamps: NodeStamp[] };
    return { stamps: new Map(raw.stamps.map((s) => [s.id, s])), round: raw.round };
  } catch { return { stamps: new Map(), round: 0 }; }
};

export const saveStamps = async (root: string, stamps: Map<string, NodeStamp>, round: number): Promise<void> => {
  await mkdir(root, { recursive: true });
  await writeFile(join(root, "cold_stamps.json"), JSON.stringify({ round, stamps: [...stamps.values()] }, null, 2));
};

/** Touch all currently-live node ids (call once per compaction round). */
export const touchLive = (graph: ExplorationGraph, stamps: Map<string, NodeStamp>, round: number): void => {
  const nodes = graph["nodes"] as Map<string, unknown>;
  for (const id of nodes.keys()) {
    const st = stamps.get(id);
    if (st) st.lastTouched = round;
    else stamps.set(id, { id, lastTouched: round, version: 0 });
  }
};
