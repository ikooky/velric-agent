import { promises as dns } from "node:dns";

/** One resolution path for discovery and the DNS tool. An explicit resolver
 * list is authoritative: never leak queries to the system resolver. */
export interface ResolveResult {
  readonly a: string[];
  readonly aaaa: string[];
  readonly cname: string[];
  readonly errors?: Partial<Record<"A" | "AAAA" | "CNAME", string>>;
}
export const resolveWith = async (host: string, resolvers?: readonly string[]): Promise<ResolveResult> => {
  const errors: Partial<Record<"A" | "AAAA" | "CNAME", string>> = {};
  let source: Pick<typeof dns, "resolve4" | "resolve6" | "resolveCname"> = dns;
  if (resolvers?.length) {
    const resolver = new dns.Resolver();
    try { resolver.setServers([...resolvers]); } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      return { a: [], aaaa: [], cname: [], errors: { A: message, AAAA: message, CNAME: message } };
    }
    source = resolver as typeof source;
  }
  const query = async (type: "A" | "AAAA" | "CNAME", fn: () => Promise<string[]>): Promise<string[]> => {
    try { return [...new Set(await fn())].sort(); }
    catch (e) {
      const err = e as NodeJS.ErrnoException;
      if (!["ENODATA", "ENOTFOUND", "NOTFOUND", "NXDOMAIN"].includes(err.code ?? "")) errors[type] = err.message ?? String(e);
      return [];
    }
  };
  const [a, aaaa, cname] = await Promise.all([
    query("A", () => source.resolve4(host)), query("AAAA", () => source.resolve6(host)), query("CNAME", () => source.resolveCname(host)),
  ]);
  return { a, aaaa, cname, ...(Object.keys(errors).length ? { errors } : {}) };
};
