import { fetchUrl } from "../adapters/http.js";

/** Subdomain enumeration: certificate transparency (crt.sh) + CNAME chain
 *  walking + small high-frequency wordlist brute force. All deterministic,
 *  zero external deps beyond HTTP. */

export interface SubdomainInput {
  readonly domain: string;
  readonly outputRoot: string;
  readonly wordlist?: string[];
  readonly resolvers?: string[];
  readonly timeoutMs?: number;
  readonly proxy?: string;
}

export interface SubdomainResult {
  readonly domain: string;
  readonly crtSh: string[];
  readonly cnameChain: { from: string; to: string }[];
  readonly bruteFound: { host: string; ips: string[] }[];
  readonly total: string[];
  readonly artifacts: { path: string; bytes: number }[];
}

import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** High-frequency subdomain prefixes worth resolving even without CT logs. */
export const SUBDOMAIN_WORDLIST: readonly string[] = [
  "www", "api", "app", "admin", "manage", "console", "dashboard", "dev", "test", "stage", "staging",
  "uat", "pre", "gray", "beta", "demo", "internal", "intra", "vpn", "oa", "mail", "smtp", "pop", "imap",
  "ftp", "sftp", "ssh", "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy", "k8s",
  "docker", "registry", "harbor", "nexus", "artifactory", "proxy", "gateway", "gw", "auth", "sso",
  "id", "passport", "login", "user", "member", "pay", "cashier", "order", "trade", "shop", "store",
  "mall", "search", "es", "mq", "mqconsole", "redis", "mysql", "db", "pg", "mongo", "clickhouse",
  "grafana", "prometheus", "kibana", "elastic", "log", "logs", "sentry", "zipkin", "jaeger", "skywalking",
  "monitor", "status", "health", "metrics", "docs", "doc", "wiki", "confluence", "jira", "wiki2",
  "static", "cdn", "img", "image", "images", "asset", "assets", "res", "file", "files", "download",
  "upload", "oss", "s3", "cos", "obs", "media", "video", "live", "push", "im", "msg", "notify",
  "open", "openapi", "gateway-open", "third", "partner", "callback", "hook", "hooks", "webhook",
  "mobile", "m", "h5", "wap", "mini", "pc", "web", "www2", "new", "old", "v2", "v3", "beta2",
  "sandbox", "prod", "production", "online", "release", "canary", "edge", "node1", "node2",
];

/** Certificate-transparency fallback chain: crt.sh first, CertSpotter when
 *  crt.sh is down/overloaded (502 is common). Each source is best-effort. */
const certSpotterQuery = async (domain: string, timeoutMs?: number, proxy?: string): Promise<string[]> => {
  try {
    const res = await fetchUrl(
      `https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`,
      { timeoutMs: timeoutMs ?? 20000, proxy },
    );
    if (res.status !== 200) return sourcegraphQuery(domain, timeoutMs, proxy);
    const out = new Set<string>();
    // Issuances JSON: [{ dns_names: [...] }, ...] — tolerate text-tolerant parse.
    for (const m of res.body.matchAll(/"dns_names"\s*:\s*\[([^\]]*)\]/g)) {
      for (const n of m[1]!.matchAll(/"([^"]+)"/g)) {
        const host = n[1]!.toLowerCase().replace(/^\*\./, "");
        if (host.endsWith(domain)) out.add(host);
      }
    }
    const found = [...out];
    return found.length === 0 ? sourcegraphQuery(domain, timeoutMs, proxy) : found;
  } catch {
    return [];
  }
};

/** Third CT/leak source: Sourcegraph stream search (free, no key). Best
 *  effort — intermittent backend, so only used when both CT sources fail. */
const sourcegraphQuery = async (domain: string, timeoutMs?: number, proxy?: string): Promise<string[]> => {
  try {
    const res = await fetchUrl(
      `https://sourcegraph.com/.api/search/stream?q=context:global+${encodeURIComponent(`"${domain}"`)}+count:200&v=V3&t=literal&display=100`,
      { timeoutMs: timeoutMs ?? 15000, proxy },
    );
    if (res.status !== 200) return [];
    const out = new Set<string>();
    // SSE lines: data: [...] with repo/path content events; hostnames appear in matches
    const hostRe = new RegExp("([a-z0-9-]+\\.)*" + domain.replace(/\./g, "\\."), "gi");
    for (const m of res.body.matchAll(hostRe)) {
      out.add(m[0].toLowerCase());
    }
    return [...out].filter((h) => h.endsWith(domain));
  } catch {
    return [];
  }
};

const crtShQuery = async (domain: string, timeoutMs?: number, proxy?: string): Promise<string[]> => {
  try {
    const res = await fetchUrl(
      `https://crt.sh/?q=%25.${domain}&output=json`,
      { timeoutMs: timeoutMs ?? 20000, proxy },
    );
    if (res.status !== 200) return certSpotterQuery(domain, timeoutMs, proxy);
    const out = new Set<string>();
    for (const m of res.body.matchAll(/"common_name"\s*:\s*"([^"]+)"/g)) out.add(m[1]!.toLowerCase());
    for (const m of res.body.matchAll(/"name_value"\s*:\s*"([^"]+)"/g)) {
      for (const n of m[1]!.split("\\n")) out.add(n.trim().toLowerCase());
    }
    const found = [...out].filter((h) => h.endsWith(domain));
    if (found.length === 0) return certSpotterQuery(domain, timeoutMs, proxy);
    return found;
  } catch {
    return certSpotterQuery(domain, timeoutMs, proxy);
  }
};

interface DnsAnswer { type: string; value: string }

const resolve = async (
  host: string,
  resolvers?: string[],
): Promise<{ a: string[]; cname: string[] }> => {
  const { resolve4, resolveCname, Resolver } = await import("node:dns").then((m) => m.promises);
  try {
    const a = await resolve4(host);
    return { a, cname: [] };
  } catch { /* next */ }
  try {
    const cname = await resolveCname(host);
    return { a: [], cname };
  } catch { /* next */ }
  if (resolvers && resolvers.length > 0) {
    try {
      const r = new Resolver();
      r.setServers(resolvers);
      const a: string[] = await r.resolve4(host);
      return { a, cname: [] };
    } catch { /* give up */ }
  }
  return { a: [], cname: [] };
};

export const discoverSubdomains = async (
  input: SubdomainInput,
): Promise<SubdomainResult> => {
  const domain = input.domain.replace(/^\*\*\./, "").replace(/^\*\./, "").trim().toLowerCase();
  await mkdir(input.outputRoot, { recursive: true });

  // 1) Certificate transparency
  const crtSh = await crtShQuery(domain, input.timeoutMs, input.proxy);

  // 2) CNAME chain from the apex + www
  const cnameChain: { from: string; to: string }[] = [];
  const seen = new Set<string>([domain]);
  let frontier = [domain, `www.${domain}`];
  while (frontier.length > 0 && cnameChain.length < 20) {
    const next: string[] = [];
    for (const host of frontier) {
      const { cname } = await resolve(host, input.resolvers);
      for (const c of cname) {
        const target = c.toLowerCase().replace(/\.$/, "");
        if (seen.has(target)) continue;
        seen.add(target);
        cnameChain.push({ from: host, to: target });
        next.push(target);
      }
    }
    frontier = next.slice(0, 10);
  }

  // 3) Wordlist brute (bounded concurrency)
  const wordlist = input.wordlist ?? SUBDOMAIN_WORDLIST;
  const bruteFound: { host: string; ips: string[] }[] = [];
  const queue = [...wordlist];
  const worker = async (): Promise<void> => {
    while (queue.length > 0) {
      const w = queue.shift()!;
      const host = `${w}.${domain}`;
      const { a } = await resolve(host, input.resolvers);
      if (a.length > 0) bruteFound.push({ host, ips: a });
    }
  };
  await Promise.all(Array.from({ length: 12 }, worker));

  const total = [...new Set([...crtSh, ...bruteFound.map((b) => b.host)])].sort();

  const path = join(input.outputRoot, "subdomains.txt");
  const body = total.join("\n");
  await writeFile(path, body);
  return {
    domain,
    crtSh: crtSh.sort(),
    cnameChain,
    bruteFound: bruteFound.sort((x, y) => x.host.localeCompare(y.host)),
    total,
    artifacts: [{ path, bytes: Buffer.byteLength(body) }],
  };
};
