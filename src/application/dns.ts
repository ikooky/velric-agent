import { resolveWith } from "../domain/dnsResolve.js";
export interface DnsAnswer { readonly type: "A" | "AAAA" | "CNAME"; readonly value: string }
export interface DnsResult { readonly host: string; readonly answers: DnsAnswer[]; readonly error?: string }
export const resolveHost = async (host: string, resolvers?: readonly string[]): Promise<DnsResult> => {
  const r = await resolveWith(host, resolvers);
  const answers: DnsAnswer[] = [
    ...r.a.map(value => ({ type: "A" as const, value })),
    ...r.aaaa.map(value => ({ type: "AAAA" as const, value })),
    ...r.cname.map(value => ({ type: "CNAME" as const, value })),
  ];
  const errors = Object.entries(r.errors ?? {}).map(([type, error]) => `${type}: ${error}`);
  return { host, answers, ...(errors.length ? { error: errors.join("; ") } : {}) };
};
