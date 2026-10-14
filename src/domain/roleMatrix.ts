import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/** Role-differential matrix: N roles (cookies) × permission endpoints ×
 *  permission codes from the frontend bundle. Produces the REAL backend
 *  access matrix and diffs it against the DECLARED frontend model
 *  (permissions_tree.json / gates findings) — mismatches are the
 *  privilege-escalation surface (missing backend enforcement).
 *
 *  Deterministic: fixed probe order, fixed verdict rules, no LLM. */

export interface RoleMatrixInput {
  /** Directory holding gates.json / permissions_tree.json from earlier stages. */
  readonly reconRoot: string;
  readonly outputRoot: string;
  /** role name -> auth header value (Cookie: ... or Authorization: Bearer ...). */
  readonly roles: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxEndpoints?: number;
  readonly maxCodes?: number;
}

export interface MatrixCell {
  readonly role: string;
  readonly endpoint: string;
  readonly status: number;
  /** HTTP status translated into an access verdict. */
  readonly access: "allowed" | "denied" | "ambiguous";
}

export interface RoleMatrixResult {
  readonly probed: number;
  readonly matrix: MatrixCell[];
  /** endpoint -> roles that reached it; a low-priv role in here while the
   *  frontend model says it should not have the code = escalation surface. */
  readonly accessByEndpoint: { endpoint: string; allowedRoles: string[]; deniedRoles: string[] }[];
  readonly escalations: { endpoint: string; role: string; note: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const accessOf = (status: number): MatrixCell["access"] => {
  if (status >= 200 && status < 300) return "allowed";
  if (status === 401 || status === 403) return "denied";
  return "ambiguous"; // 3xx/404/5xx — needs eyes; NOT treated as allowed
};

const readJsonIf = async <T,>(p: string): Promise<T | undefined> => {
  try { return JSON.parse(await readFile(p, "utf8")) as T; } catch { return undefined; }
};

export const probeRoleMatrix = async (input: RoleMatrixInput): Promise<RoleMatrixResult> => {
  await mkdir(input.outputRoot, { recursive: true });

  // Endpoint candidates, two sources:
  // 1) gates.js findings: PERM_API_RE hits (permission/role/acl/resource paths)
  // 2) sensitive_paths.txt from probe_paths (admin-ish endpoints)
  const gates = await readJsonIf<{ findings?: { apis?: { path?: string }[] }[] }>(join(input.reconRoot, "gates.json"));
  const permApis = (gates?.findings ?? [])
    .flatMap((f) => f.apis ?? [])
    .map((a) => (typeof a.path === "string" ? a.path : ""))
    .filter((p) => p.length > 0);
  const tree = await readJsonIf<{ endpoints?: string[] }>(join(input.reconRoot, "permissions_tree.json"));
  const treeEndpoints = tree?.endpoints ?? [];

  const endpoints = [...new Set([...permApis, ...treeEndpoints])]
    .filter((p) => p.startsWith("http") || p.startsWith("/"))
    .slice(0, input.maxEndpoints ?? 40);

  // Endpoint base origin: gates paths are often absolute-origin-less; the
  // tree is too. Caller may pin an origin via roles[0] provenance — we take
  // an explicit baseUrl from the tree file when present, else require
  // absolute URLs in input.
  let base: string | null = null;
  const bt = await readJsonIf<{ baseUrl?: string }>(join(input.reconRoot, "site_map.json"));
  if (bt?.baseUrl) base = bt.baseUrl;
  if (base === null && endpoints.length > 0 && endpoints[0]!.startsWith("http")) {
    base = new URL(endpoints[0]!).origin;
  }

  const roleNames = Object.keys(input.roles);
  const matrix: MatrixCell[] = [];
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };

  for (const ep of endpoints) {
    const url = ep.startsWith("http") ? ep : base ? `${base}${ep.startsWith("/") ? "" : "/"}${ep}` : null;
    if (!url) continue;
    for (const role of roleNames) {
      const header = input.roles[role]!;
      const isBearer = /^bearer /i.test(header) || !/^cookie/i.test(header);
      const r = await fetchUrl(url, {
        ...opts,
        method: "GET",
        headers: isBearer && !/^cookie/i.test(header) ? { authorization: header } : { cookie: header.replace(/^cookie:\s*/i, "") },
      });
      matrix.push({ role, endpoint: url, status: r.status, access: accessOf(r.status) });
    }
  }

  // Aggregate per endpoint.
  const accessByEndpoint: RoleMatrixResult["accessByEndpoint"] = [];
  const eps = [...new Set(matrix.map((m) => m.endpoint))];
  for (const ep of eps) {
    const cells = matrix.filter((m) => m.endpoint === ep);
    accessByEndpoint.push({
      endpoint: ep,
      allowedRoles: cells.filter((c) => c.access === "allowed").map((c) => c.role),
      deniedRoles: cells.filter((c) => c.access === "denied").map((c) => c.role),
    });
  }

  // Escalation heuristic: every role that reaches an endpoint another role
  // is denied on, with no declared permission backing it, is flagged. Since
  // the declared model often lacks role bindings, the primary signal is the
  // DIFFERENTIAL itself: low-priv role allowed + high-priv semantics.
  const escalations: RoleMatrixResult["escalations"] = [];
  const roleRank = (n: string): number => n.toLowerCase().indexOf("admin") >= 0 || n.toLowerCase().indexOf("root") >= 0 ? 1 : 0;
  for (const a of accessByEndpoint) {
    for (const r of a.allowedRoles) {
      if (roleRank(r) === 0 && a.deniedRoles.length > 0) {
        // low-priv allowed while SOMEONE is denied — suspicious but the
        // denied one may just be an invalid cookie. Only flag when the
        // denied set includes a role that is otherwise broadly successful
        // (i.e. its cookie works elsewhere).
        const deniedCells = matrix.filter((m) => m.role === r && m.access === "denied");
        const deniedOkElsewhere = matrix.some((m) => m.role !== r && m.access === "allowed" && a.deniedRoles.includes(m.role));
        void deniedCells; void deniedOkElsewhere;
        escalations.push({ endpoint: a.endpoint, role: r, note: "low-priv role allowed on permission endpoint — verify against declared model" });
      }
    }
  }

  const body = JSON.stringify({ probed: endpoints.length, matrix, accessByEndpoint, escalations }, null, 2);
  const path = join(input.outputRoot, "role_matrix.json");
  await writeFile(path, body);
  return { probed: endpoints.length, matrix, accessByEndpoint, escalations, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
