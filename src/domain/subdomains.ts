import { fetchUrl } from "../adapters/http.js";
import { resolveWith, type ResolveResult } from "./dnsResolve.js";
import { randomUUID } from "node:crypto";

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
  /** Multiple random labels resolve; only matching wildcard answers are filtered. */
  readonly wildcardDns: boolean;
  /** dangling-CNAME takeover candidates (service fingerprint matches). */
  readonly takeovers?: { host: string; cname: string; service: string; note: string }[];
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
        if (host === domain || host.endsWith("." + domain)) out.add(host);
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
    return [...out].filter((h) => h === domain || h.endsWith("." + domain));
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
    const found = [...out].filter((h) => h === domain || h.endsWith("." + domain));
    if (found.length === 0) return certSpotterQuery(domain, timeoutMs, proxy);
    return found;
  } catch {
    return certSpotterQuery(domain, timeoutMs, proxy);
  }
};

const resolve = (host: string, resolvers?: string[]): Promise<ResolveResult> =>
  resolveWith(host, resolvers);

export const validDiscoveryHost = (host: string): boolean => host.length <= 253 && host.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
const dnsValues = (answer: ResolveResult): string[] => [
  ...answer.a.map(ip => `A:${ip}`), ...(answer.aaaa ?? []).map(ip => `AAAA:${ip}`),
  ...answer.cname.map(name => `CNAME:${name.toLowerCase().replace(/\.$/, "")}`),
];
export interface WildcardCalibration { readonly detected: boolean; readonly values: ReadonlySet<string> }
export const calibrateWildcard = async (domain: string, resolvers?: readonly string[]): Promise<WildcardCalibration> => {
  const answers = await Promise.all(Array.from({ length: 3 }, () => resolveWith(`zz-${randomUUID()}.${domain}`, resolvers)));
  const successful = answers.filter(a => !a.errors && dnsValues(a).length > 0);
  return { detected: successful.length >= 2, values: new Set(successful.flatMap(dnsValues)) };
};
export const matchesWildcard = (answer: ResolveResult, baseline: WildcardCalibration): boolean => {
  const values = dnsValues(answer);
  return baseline.detected && !answer.errors && values.length > 0 && values.every(v => baseline.values.has(v));
};

export const discoverSubdomains = async (
  input: SubdomainInput,
): Promise<SubdomainResult> => {
  const domain = input.domain.replace(/^\*\*\./, "").replace(/^\*\./, "").trim().toLowerCase();
  if (!validDiscoveryHost(domain)) throw new Error("invalid discovery domain");
  await mkdir(input.outputRoot, { recursive: true });

  // 1) Certificate transparency
  const crtSh = [...new Set((await crtShQuery(domain, input.timeoutMs, input.proxy)).map(h => h.replace(/^\*\./, "").toLowerCase()).filter(h => validDiscoveryHost(h) && (h === domain || h.endsWith(`.${domain}`))))];

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

  // 3) Wordlist brute (bounded concurrency). Wildcard DNS guard first: if a
  //  random label resolves, EVERY word would "resolve" — record the wildcard
  //  and drop brute results entirely instead of ~100 phantom hosts.
  const wordlist = input.wordlist ?? SUBDOMAIN_WORDLIST;
  const bruteFound: { host: string; ips: string[] }[] = [];
  const wildcard = await calibrateWildcard(domain, input.resolvers);
  {
    const queue = [...wordlist].filter(w => typeof w === "string" && validDiscoveryHost(w)).slice(0, 2000);
    const worker = async (): Promise<void> => {
      while (queue.length > 0) {
        const w = queue.shift()!;
        const host = `${w}.${domain}`;
        const answer = await resolve(host, input.resolvers);
        if (matchesWildcard(answer, wildcard)) continue;
        const ips = [...answer.a, ...(answer.aaaa ?? [])];
        if (ips.length > 0 || answer.cname.length > 0) bruteFound.push({ host, ips });
        for (const target of answer.cname) {
          const to = target.toLowerCase().replace(/\.$/, "");
          if (!cnameChain.some(edge => edge.from === host && edge.to === to)) cnameChain.push({ from: host, to });
        }
      }
    };
    await Promise.all(Array.from({ length: 12 }, worker));
  }

  const total = [...new Set([...crtSh, ...bruteFound.map((b) => b.host)])].sort();

  // 4) Subdomain-takeover fingerprints (takeovers.edgewecurity-style): CNAME
  //    chains already collected — match dangling targets against known
  //    service fingerprint table + NXDOMAIN-friendly indicators.
  const takeovers = detectTakeovers(cnameChain, total);

  const path = join(input.outputRoot, "subdomains.txt");
  const body = total.join("\n");
  await writeFile(path, body);
  return {
    domain,
    crtSh: crtSh.sort(),
    cnameChain,
    bruteFound: bruteFound.sort((x, y) => x.host.localeCompare(y.host)),
    wildcardDns: wildcard.detected,
    takeovers,
    total,
    artifacts: [{ path, bytes: Buffer.byteLength(body) }],
  };
};

/** Dangling-service fingerprints: CNAME target pattern -> service. A hit is a
 *  TAKEOVER CANDIDATE (verify the service response body for the canonical
 *  "nobody has claimed this site" string before reporting). */
const TAKEOVER_FINGERPRINTS: ReadonlyArray<readonly [string, RegExp]> = [
  ["github_pages", /\.github\.io$/i],
  ["heroku", /\.herokuapp\.com$/i],
  ["heroku_dns", /\.herokudns\.com$/i],
  ["aws_s3", /(?:^|\.)s3[.-](?:amazonaws|external-1\.amazonaws)\.com$/i],
  ["aws_s3_website", /\.s3-website[-.][a-z0-9-]*\.amazonaws\.com$/i],
  ["cloudfront", /\.cloudfront\.net$/i],
  ["fastly", /\.fastly\.net$/i],
  ["azure_cloud", /\.cloudapp\.(?:net|azure\.com)$/i],
  ["azure_websites", /\.azurewebsites\.net$/i],
  ["azure_trafficmanager", /\.trafficmanager\.net$/i],
  ["pantheon", /\.pantheonsite\.io$/i],
  ["readme", /\.readme\.io$/i],
  ["helpjuice", /\.helpjuice\.com$/i],
  ["helpscout", /\.helpscoutdocs\.com$/i],
  ["bitbucket", /\.bitbucket\.io$/i],
  ["ghost", /\.ghost\.io$/i],
  ["tumblr", /\.tumblr\.com$/i],
  ["wordpress", /\.wordpress\.com$/i],
  ["unbounce", /\.unbouncepages\.com$/i],
  ["cargocollective", /\.cargocollective\.com$/i],
  ["statuspage", /\.statuspage\.io$/i],
  ["surge", /\.surge\.sh$/i],
  ["netlify", /\.netlify\.app$/i],
  ["vercel", /\.vercel\.app$/i],
  ["firebaseio", /\.firebaseio\.com$/i],
  ["webflow", /\.webflow\.io$/i],
];

/** Match collected CNAME chains against the fingerprint table. Only chains
 *  whose target matches a takeover-capable service are listed; confirmation
 *  (service body check) stays with the host — this is a candidate list. */
export const detectTakeovers = (
  cnameChain: readonly { from: string; to: string }[],
  _allHosts: readonly string[],
): { host: string; cname: string; service: string; note: string }[] => {
  const out: { host: string; cname: string; service: string; note: string }[] = [];
  for (const { from, to } of cnameChain) {
    for (const [service, re] of TAKEOVER_FINGERPRINTS) {
      if (re.test(to)) {
        out.push({ host: from, cname: to, service, note: "dangling-service candidate — fetch and verify the claim page body" });
        break;
      }
    }
  }
  return out;
};
