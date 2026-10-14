import { promises as dns } from "node:dns";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
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

export const writeArtifact = async (
  root: string,
  rel: string,
  data: string,
): Promise<{ path: string; bytes: number }> => {
  const full = join(root, rel);
  await mkdir(dirname(full), { recursive: true });
  await writeFile(full, data, "utf8");
  return { path: full, bytes: Buffer.byteLength(data) };
};

const rootOf = (host: string): string => {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  // naive eTLD+1: last two labels (adequate for pentest seed lists)
  return parts.slice(-2).join(".");
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
    upsert({ type: "root_domain", key: root, rootDomain: root });
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
        const probe = await httpProbe({ url,
          proxy: input.proxy, cookie: input.cookie, timeoutMs: input.timeoutMs,
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
  const list = [...assets.values()];
  const counts: Record<string, number> = {};
  for (const a of list) counts[a.type] = (counts[a.type] ?? 0) + 1;
  const artifacts = [
    await writeArtifact(input.outputRoot, "assets.json", JSON.stringify(list, null, 2)),
  ];
  return { assets: list, counts, artifacts };
};
