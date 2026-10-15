/** Subdomain alteration engine (Amass/gotator-style): takes KNOWN subdomains
 *  (from CT logs / brute) and generates permutation candidates — prefix
 *  inserts, suffix inserts, dashes, digit increments, label splits and
 *  common ops-vocabulary cross products — then resolves them. Real fleets
 *  have dev2 next to dev, api-qa next to api; permutation finds hosts that
 *  no wordlist and no CT log contains.
 *
 *  Pure string transforms + existing dns_resolve — deterministic. */

import { resolveWith } from "./dnsResolve.js";

export interface AlterationInput {
  /** known subdomain hosts (e.g. from subdomain_enum output). */
  readonly hosts: readonly string[];
  readonly domain: string;
  /** resolve candidates? default true. false = generate only (dry). */
  readonly resolve?: boolean;
  readonly maxCandidates?: number;
  /** nameservers passed through to dns resolver. */
  readonly nameservers?: readonly string[];
  readonly concurrency?: number;
}

export interface AlterationResult {
  readonly generated: number;
  readonly resolved: { host: string; ips: string[]; cname?: string }[];
  /** unique permutation samples for the report. */
  readonly samples: string[];
}

/** ops vocabulary that prefixes/suffixes real labels in fleets. */
const AFFIX_WORDS = [
  "api", "app", "admin", "stage", "staging", "dev", "test", "qa", "uat", "prod", "production",
  "internal", "ext", "external", "beta", "demo", "gray", "pre", "preprod", "sit",
  "v2", "v3", "new", "old", "backup", "bak", "tmp", "sandbox", "mirror", "edge",
  "us", "eu", "cn", "jp", "sg", "global", "c1", "c2",
];

const generate = (host: string, domain: string): string[] => {
  const label = host.slice(0, host.length - domain.length - 1); // strip .domain
  if (!label || label.includes("*")) return [];
  const out = new Set<string>();
  const parts = label.split(".");
  const leaf = parts[parts.length - 1]!;
  const stem = leaf.replace(/\d+$/, "");

  for (const w of AFFIX_WORDS) {
    // prefix: dev.api.example.com
    out.add(`${w}.${host}`);
    // suffix: api-dev.example.com / api2.example.com
    out.add(`${leaf}-${w}.${domain === host ? domain : label.split(".").slice(0, -1).concat(`${leaf}-${w}`).join(".") + "." + domain}`);
    out.add(`${stem}${w}.${label.split(".").slice(0, -1).join(".") ? label.split(".").slice(0, -1).join(".") + "." : ""}${domain}`);
    // number increments: api2 / dev1
    const m = leaf.match(/^(.*?)(\d+)$/);
    if (m) {
      const n = Number(m[2]);
      out.add(`${m[1]}${n + 1}.${label.split(".").slice(0, -1).join(".") ? label.split(".").slice(0, -1).join(".") + "." : ""}${domain}`);
    } else if (w === "v2" || w === "2") {
      out.add(`${leaf}2.${label.split(".").slice(0, -1).join(".") ? label.split(".").slice(0, -1).join(".") + "." : ""}${domain}`);
    }
  }
  // dash-join parents: a.b.example.com -> a-b.example.com
  if (parts.length >= 2) {
    out.add(`${parts.join("-")}.${domain}`);
    out.add(`${parts.slice().reverse().join(".")}.${domain}`);
  }
  return [...out].filter((h) => h !== host && h.endsWith("." + domain) && h.length < 100);
};

export const alterSubdomains = async (input: AlterationInput): Promise<AlterationResult> => {
  const generated = new Set<string>();
  for (const h of input.hosts) {
    if (!h.endsWith("." + input.domain)) continue;
    for (const c of generate(h, input.domain)) generated.add(c);
  }
  const candidates = [...generated].slice(0, input.maxCandidates ?? 800);

  if (input.resolve === false || candidates.length === 0) {
    return { generated: candidates.length, resolved: [], samples: candidates.slice(0, 20) };
  }

  const resolved: AlterationResult["resolved"] = [];
  const conc = input.concurrency ?? 40;
  let idx = 0;
  const worker = async (): Promise<void> => {
    while (idx < candidates.length) {
      const host = candidates[idx++]!;
      try {
        const { a, cname } = await resolveWith(host, input.nameservers);
        if (a.length > 0) resolved.push({ host, ips: a });
        else if (cname.length > 0) resolved.push({ host, ips: [], cname: cname[0] });
      } catch { /* unresolved — expected for most candidates */ }
    }
  };
  await Promise.all(Array.from({ length: Math.min(conc, candidates.length) }, worker));

  return { generated: candidates.length, resolved, samples: candidates.slice(0, 20) };
};
