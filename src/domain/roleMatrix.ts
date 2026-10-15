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
      // Accept both the bare credential ("Bearer x", "x=y;…") and the full
      // header form ("Authorization: Bearer x", "Cookie: a=b").
      const isAuthHeader = /^authorization\s*:/i.test(header);
      const isCookieHeader = /^cookie\s*:/i.test(header);
      const isBearerValue = /^bearer\s+\S/i.test(header);
      const headers: Record<string, string> = isAuthHeader || isBearerValue
        ? { authorization: header.replace(/^authorization\s*:\s*/i, "") }
        : { cookie: isCookieHeader ? header.replace(/^cookie\s*:\s*/i, "") : header };
      const r = await fetchUrl(url, { ...opts, method: "GET", headers });
      // Redirect-followed responses landing on a DIFFERENT path (typically
      // the login page) are auth redirects, not access: a 302→/login chain
      // ending in 200 must never score as "allowed" for that role.
      let landed = "";
      try { landed = new URL(r.finalUrl ?? url).pathname.replace(/\/$/, ""); } catch { landed = ""; }
      const probed = new URL(url).pathname.replace(/\/$/, "");
      // landed=="" means the root "/" — still a different page than the
      // protected one when the probe was NOT for "/" itself.
      const redirectedAway = r.finalUrl != null && landed !== probed;
      // 2xx is not "allowed" on its own: many gateways answer 200 with a
      // JSON access-denied body. Downgrade to ambiguous when the body smells
      // like a denial (differential discipline: content, not bare status).
      const deniedish = r.status >= 200 && r.status < 300 && /access[- ]?denied|forbidden|unauthori[sz]ed|permission denied/i.test(r.body.slice(0, 2048));
      const access = redirectedAway ? "denied" : deniedish ? "ambiguous" : accessOf(r.status);
      matrix.push({ role, endpoint: url, status: r.status, access });
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
  // A denied role's verdict only counts when its credential WORKS somewhere
  // (allowed on >=1 other endpoint) — otherwise "denied everywhere" is just
  // an expired cookie, not evidence of enforcement.
  const credentialWorks = (role: string): boolean => matrix.some((m) => m.role === role && m.access === "allowed");
  for (const a of accessByEndpoint) {
    const credibleDenied = a.deniedRoles.filter(credentialWorks);
    for (const r of a.allowedRoles) {
      if (roleRank(r) === 0 && credibleDenied.length > 0) {
        escalations.push({ endpoint: a.endpoint, role: r, note: `low-priv role allowed while ${credibleDenied.join(",")} (valid creds) denied — verify against declared model` });
      }
    }
  }

  const body = JSON.stringify({ probed: endpoints.length, matrix, accessByEndpoint, escalations }, null, 2);
  const path = join(input.outputRoot, "role_matrix.json");
  await writeFile(path, body);
  return { probed: endpoints.length, matrix, accessByEndpoint, escalations, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
