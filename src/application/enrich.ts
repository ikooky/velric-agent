import { PUBLIC_MULTI_SUFFIX } from "../domain/graphs.js";
import { promises as dns } from "node:dns";
import { join } from "node:path";
import { httpProbe } from "./probe.js";

/** velric asset-graph node kinds (db/assets.go). */
export type AssetKind =
  | "root_domain"
  | "domain"
  | "subdomain"
  | "ip"
  | "service"
  | "endpoint"
  | "app"
  | "port";

export interface AssetNode {
  readonly type: AssetKind;
  readonly key: string; // domain / ip / url / host:port
  readonly rootDomain?: string;
  readonly recordType?: string; // A / AAAA / CNAME
  readonly recordValue?: string[];
  readonly ip?: string;
  readonly url?: string;
  readonly method?: string;
  readonly port?: number;
  readonly serviceType?: string; // http
  readonly serviceName?: string;
  readonly pageTitle?: string;
}

export interface EnrichInput {
  readonly seeds: string[]; // domains or URLs
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly cookie?: string;
  readonly timeoutMs?: number;
  readonly maxAssets?: number;
  readonly http?: boolean; // probe http services (default true)
}

export interface EnrichResult {
  readonly assets: AssetNode[];
  readonly counts: Record<string, number>;
  readonly artifacts: { path: string; bytes: number }[];
}

// The guarded writer (absolute-root assertion + path-escape refusal) —
// a local join()+writeFile copy silently lost that protection.
import { writeArtifact as guardedWriteArtifact } from "../adapters/artifacts.js";
export const writeArtifact = guardedWriteArtifact;

const rootOf = (host: string): string => {
  // Same algorithm as graphs.ts MULTI_SUFFIX: two-label suffixes that are
  // public suffixes (co.uk et al) need the eTLD+1 to be three labels —
  // naive last-2 returned "co.uk" for "target.co.uk".
  const MULTI_SUFFIX = PUBLIC_MULTI_SUFFIX;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join(".");
  return MULTI_SUFFIX.has(last2) ? parts.slice(-3).join(".") : last2;
};

const resolveHost = async (
  host: string,
  errors: string[],
): Promise<{ a: string[]; aaaa: string[]; cname: string[] }> => {
  const out = { a: [] as string[], aaaa: [] as string[], cname: [] as string[] };
  await Promise.all([
    dns.resolve4(host).then((r) => { out.a = r; }).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== "ENODATA" && e.code !== "NOTFOUND") errors.push(`A ${host}: ${e.message}`);
    }),
    dns.resolve6(host).then((r) => { out.aaaa = r; }).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== "ENODATA" && e.code !== "NOTFOUND") errors.push(`AAAA ${host}: ${e.message}`);
    }),
    dns.resolveCname(host).then((r) => { out.cname = r; }).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== "ENODATA" && e.code !== "NOTFOUND") errors.push(`CNAME ${host}: ${e.message}`);
    }),
  ]);
  return out;
};

export const enrichAssets = async (input: EnrichInput): Promise<EnrichResult> => {
  const errors: string[] = [];
  const assets = new Map<string, AssetNode>();
  const upsert = (n: AssetNode) => {
    const k = `${n.type}:${n.key}`;
    const prev = assets.get(k);
    if (!prev) { assets.set(k, n); return; }
    assets.set(k, {
      ...prev,
      ...Object.fromEntries(Object.entries(n).filter(([, v]) => v !== undefined && v !== null)),
    } as AssetNode);
  };
  const maxAssets = input.maxAssets ?? 5000;

  for (const raw of input.seeds) {
    if (assets.size >= maxAssets) break;
    const isUrl = /^https?:\/\//i.test(raw);
    let host: string;
    if (isUrl) {
      try { host = new URL(raw).hostname; } catch { continue; }
    } else {
      host = raw.replace(/\.$/, "");
    }
    const url = isUrl ? raw : `https://${host}`;
    const root = rootOf(host);
    upsert({ type: "domain", key: host, rootDomain: root });
    // A bare public suffix (host IS "co.uk") is not a registrable domain —
    // graphs.ts already refuses these; keep the two implementations aligned.
    // Every other host (including a bare multi-label eTLD+1 like target.co.uk
    // or a two-label example.com) gets a root_domain node.
    {
      const PUBLIC_SUFFIX = PUBLIC_MULTI_SUFFIX;
      if (!PUBLIC_SUFFIX.has(host)) upsert({ type: "root_domain", key: root, rootDomain: root });
    }
    try {
      const rec = await resolveHost(host, errors);
      for (const a of rec.a) {
        upsert({ type: "ip", key: a, rootDomain: root });
        upsert({ type: "subdomain", key: host, rootDomain: root, recordType: "A", recordValue: [a] });
      }
      for ( const aaaa of rec.aaaa) {
        upsert({ type: "ip", key: aaaa, rootDomain: root });
        upsert({ type: "subdomain", key: host, rootDomain: root, recordType: "AAAA", recordValue: [aaaa] });
      }
      for (const cn of rec.cname) {
        upsert({ type: "subdomain", key: host, rootDomain: root, recordType: "CNAME", recordValue: [cn] });
      }
      if (input.http !== false) {
        // Session cookies are scoped to the FIRST seed's registrable domain —
        // never replayed to arbitrary hosts from third-party seed lists
        // (same-origin discipline as harvest/spider).
        const firstSeed = input.seeds[0] ?? "";
        const firstRoot = (() => { try { return rootOf(new URL(/^https?:\/\//i.test(firstSeed) ? firstSeed : `https://${firstSeed}`).hostname.replace(/^www\./, "")); } catch { return null; } })();
        const cookie = input.cookie && firstRoot && (root === firstRoot || host.endsWith(`.${firstRoot}`)) ? input.cookie : undefined;
        const probe = await httpProbe({ url,
          proxy: input.proxy, cookie, timeoutMs: input.timeoutMs,
        },).catch(() => null);
        if (probe && probe.status > 0) {
          upsert({
            type: "service", key: url, rootDomain: root, url,
            serviceType: "http", serviceName: "http",
            port: url.startsWith("https") ? 443 : 80,
            pageTitle: probe.title ?? undefined,
          });
        }
      }
    } catch {
      /* seed unresolvable — record domain node only */
    }
  }
  // Dual-graph write-back: every enriched asset also lands in the shared
  // asset graph so the store stays the single truth.
  const { AssetStore } = await import("../domain/graphs.js");
  const assetStore = new AssetStore(input.outputRoot);
  await assetStore.load();
  for (const a of assets.values()) {
    if (a.type === "root_domain") assetStore.upsert({ type: "root_domain", value: a.key });
    else if (a.type === "domain" || a.type === "subdomain") assetStore.upsert({ type: "subdomain", value: a.key });
    else if (a.type === "ip") assetStore.upsert({ type: "ip", value: a.key });
    else if (a.type === "service" && a.url) assetStore.upsert({ type: "service", value: a.key, meta: { pageTitle: (a as { pageTitle?: string }).pageTitle } });
  }
  await assetStore.save();
  const assetSyncSummary = { upserted: assets.size, counts: assetStore.countsByType() };

  const list = [...assets.values()];
  const counts: Record<string, number> = {};
  for (const a of list) counts[a.type] = (counts[a.type] ?? 0) + 1;
  const artifacts = [
    await writeArtifact(input.outputRoot, "assets.json", JSON.stringify(list, null, 2)),
    // perRunCounts mirrors the fresh-run return shape so resume readers get
    // the same numbers a fresh run would have reported (counts is cumulative).
    await writeArtifact(input.outputRoot, "asset_graph_sync.json", JSON.stringify({ ...assetSyncSummary, perRunCounts: counts }, null, 2)),
  ];
  return { assets: list, counts, artifacts };
};
