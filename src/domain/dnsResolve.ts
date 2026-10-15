/** Shared DNS resolution helpers (A / CNAME with optional custom resolvers).
 *  Extracted from subdomains.ts so the alteration engine and future DNS
 *  consumers reuse ONE resolution path instead of copy-pasting resolvers. */

export interface ResolveResult {
  readonly a: string[];
  readonly cname: string[];
}

export const resolveWith = async (host: string, resolvers?: readonly string[]): Promise<ResolveResult> => {
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
      r.setServers([...resolvers]);
      const a: string[] = await r.resolve4(host);
      return { a, cname: [] };
    } catch { /* give up */ }
  }
  return { a: [], cname: [] };
};
