import { promises as dns } from "node:dns";

export interface DnsAnswer {
  readonly type: "A" | "AAAA" | "CNAME";
  readonly value: string;
}

export interface DnsResult {
  readonly host: string;
  readonly answers: DnsAnswer[];
  readonly error?: string;
}

const dedupe = (values: string[]): string[] => [...new Set(values)].sort();

/** Resolve A/AAAA/CNAME for one host. Pure lookup, no caching, no state. */
export const resolveHost = async (host: string): Promise<DnsResult> => {
  const answers: DnsAnswer[] = [];
  const errors: string[] = [];
  const jobs: readonly (readonly ["A" | "AAAA" | "CNAME", Promise<string[]>])[] = [
    ["A", dns.resolve4(host).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== "ENODATA" && e.code !== "NOTFOUND") errors.push(`A: ${e.message}`);
      return [];
    })],
    ["AAAA", dns.resolve6(host).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== "ENODATA" && e.code !== "NOTFOUND") errors.push(`AAAA: ${e.message}`);
      return [];
    })],
    ["CNAME", dns.resolveCname(host).catch((e: NodeJS.ErrnoException) => {
      if (e.code !== "ENODATA" && e.code !== "NOTFOUND") errors.push(`CNAME: ${e.message}`);
      return [];
    })],
  ];
  const settled = await Promise.all(jobs.map(async ([type, p]) => [type, await p] as const));
  for (const [type, values] of settled) {
    for (const v of dedupe(values)) answers.push({ type, value: v });
  }
  return {
    host,
    answers,
    ...(answers.length === 0 && errors.length > 0 ? { error: errors.join("; ") } : {}),
  };
};