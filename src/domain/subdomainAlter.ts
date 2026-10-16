import { resolveWith } from "./dnsResolve.js";
import { calibrateWildcard, matchesWildcard, validDiscoveryHost } from "./subdomains.js";

export interface AlterationInput {
  readonly hosts: readonly string[];
  readonly domain: string;
  readonly resolve?: boolean;
  readonly maxCandidates?: number;
  readonly nameservers?: readonly string[];
  readonly concurrency?: number;
}
export interface AlterationResult {
  readonly generated: number;
  readonly wildcardDns: boolean;
  readonly resolved: { host: string; ips: string[]; cname?: string }[];
  readonly samples: string[];
}
const AFFIX_WORDS = [
  "api", "app", "admin", "stage", "staging", "dev", "test", "qa", "uat", "prod", "production",
  "internal", "ext", "external", "beta", "demo", "gray", "pre", "preprod", "sit",
  "v2", "v3", "new", "old", "backup", "bak", "tmp", "sandbox", "mirror", "edge",
  "us", "eu", "cn", "jp", "sg", "global", "c1", "c2",
];
const generate = (host: string, domain: string): string[] => {
  const labels = host.slice(0, -domain.length - 1).split(".");
  const leaf = labels[0];
  if (!leaf) return [];
  const out = new Set<string>();
  const withLeaf = (value: string): string => [value, ...labels.slice(1), domain].join(".");
  for (const word of AFFIX_WORDS) {
    out.add([word, ...labels, domain].join("."));
    out.add(withLeaf(`${leaf}-${word}`));
    out.add(withLeaf(`${leaf.replace(/\d+$/, "")}${word}`));
  }
  const match = leaf.match(/^(.*?)(\d+)$/);
  if (match) out.add(withLeaf(`${match[1]}${Number(match[2]) + 1}`));
  else out.add(withLeaf(`${leaf}2`));
  if (labels.length >= 2) {
    out.add(`${labels.join("-")}.${domain}`);
    out.add([...labels].reverse().concat(domain).join("."));
  }
  return [...out].filter(h => h !== host && validDiscoveryHost(h));
};
export const alterSubdomains = async (input: AlterationInput): Promise<AlterationResult> => {
  const domain = input.domain.trim().toLowerCase().replace(/\.$/, "");
  if (!validDiscoveryHost(domain)) throw new Error("invalid alteration domain");
  const generated = new Set<string>();
  for (const host of input.hosts) {
    if (typeof host !== "string" || !validDiscoveryHost(host) || !host.toLowerCase().endsWith(`.${domain}`)) continue;
    for (const candidate of generate(host.toLowerCase(), domain)) generated.add(candidate);
  }
  const max = input.maxCandidates === undefined ? 800 : Number.isSafeInteger(input.maxCandidates) && input.maxCandidates >= 0 ? Math.min(10000, input.maxCandidates) : 0;
  const candidates = [...generated].slice(0, max);
  if (input.resolve === false || candidates.length === 0) return { generated: candidates.length, wildcardDns: false, resolved: [], samples: candidates.slice(0, 20) };
  const wildcard = await calibrateWildcard(domain, input.nameservers);
  const resolved: AlterationResult["resolved"] = [];
  const concurrency = Number.isSafeInteger(input.concurrency) ? Math.min(64, Math.max(1, input.concurrency!)) : 40;
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < candidates.length) {
      const host = candidates[cursor++]!;
      const answer = await resolveWith(host, input.nameservers);
      if (matchesWildcard(answer, wildcard)) continue;
      const ips = [...answer.a, ...(answer.aaaa ?? [])];
      if (ips.length > 0 || answer.cname.length > 0) resolved.push({ host, ips, ...(answer.cname.length > 0 ? { cname: answer.cname[0] } : {}) });
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, candidates.length) }, worker));
  return { generated: candidates.length, wildcardDns: wildcard.detected, resolved: resolved.sort((a, b) => a.host.localeCompare(b.host)), samples: candidates.slice(0, 20) };
};