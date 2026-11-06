import { readFile, readdir } from "node:fs/promises";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type * as ESTree from "estree";
import { parseJavaScript, walkAst } from "./rename.js";

/** Client-side auth-gate reverse engineering (api-recon Phase 2, reference
 *  A1/A2/A3): static recipes over the harvested JS corpus that locate
 *  the three gates every protected SPA puts in front of its API surface.
 *
 *  A1 render gate      — how the app decides "logged in"
 *  A2 interceptor gate — which response code field triggers /login redirect
 *  A3 content gate     — where menus/permissions come from
 *
 *  D05 discipline: every derived value carries its provenance. Response-code
 *  comparisons are classified by BRANCH CONTROL FLOW — a value compared for
 *  equality inside a branch that redirects to /login is a FAILURE value, not
 *  a success value. Storage accesses keep their ACTUAL medium: a
 *  sessionStorage key is never suggested as a localStorage patch. All
 *  findings are candidates; executable patches are only derived from
 *  positively-evidenced success values and localStorage-medium keys. */

export interface StorageCandidate {
  readonly medium: "localStorage" | "sessionStorage";
  readonly key: string;
  readonly confidence: "candidate";
  readonly file: string;
  readonly excerpt: string;
  readonly basis: string;
}

export interface GateEvidence {
  readonly file: string;
  readonly kind: "code-comparison" | "storage-access" | "redirect-trigger";
  readonly excerpt: string;
  readonly range: [number, number];
}

export interface GateFindings {
  renderGate: {
    storageKeys: string[];
    cookieKeys: string[];
    loginStateExpressions: string[];
    decodeChain: ("plain" | "json" | "b64json" | "jwt")[];
  };
  interceptorGate: {
    codeFields: string[];
    successValues: string[];
    /** Values inferred to be FAILURE codes (login-redirect branch or !== comparisons). */
    failureValues: string[];
    redirectTriggers: string[];
  };
  contentGate: {
    permissionApiPaths: string[];
    menuApiPaths: string[];
    authMapObjects: string[];
    routeMapObjects: string[];
  };
  /** Suggested preload/HookConfig patches derived from the findings. */
  suggestedConfig: {
    localStorage: Record<string, string>;
    cookies: { name: string; value: string }[];
    neutralize: { fields: string[]; success: number | string; fieldSuccess?: Record<string, string> };
    stubs: { match: string; body: unknown }[];
  };
  /** Storage accesses with their actual medium (sessionStorage ≠ localStorage). */
  readonly storageCandidates: StorageCandidate[];
  /** Provenance for every comparison/access/redirect that produced a finding. */
  readonly evidence: GateEvidence[];
}

interface FileText {
  file: string;
  text: string;
}

const COOKIE_KEY_RE = /(?:Cookies?|cookie)\.(?:get|load|set)\(\s*["']([^"']+)["']/g;
const LOGIN_STATE_RE = /(?:isLogin|isAuthenticated|loggedIn|hasLogin|requireAuth|hasPermission|checkAuth)\s*[=!]==?\s*(?:true|"1"|'1'|1)/g;
const REDIRECT_RE = /(?:location\.href|router\.(?:push|replace)|navigate)\s*\(\s*["'][^"']*login[^"']*["']/gi;
const PERM_API_RE = /["'](\/[^"']*(?:permission|perm|role|acl|resource)[^"']*)["']/gi;
const MENU_API_RE = /["'](\/[^"']*(?:menu|menus|nav|sidebar)[^"']*)["']/gi;
const AUTHMAP_RE = /(?:userRouteAuth|getResultTree|hasPermission|checkAuth|authList)\s*=/g;
const ROUTEMAP_RE = /(?:routeMap|routeLink|menuList)\s*=/g;

/** Field names treated as response-code carriers (A2). */
const CODE_FIELD_NAMES = new Set([
  "response_code", "errcode", "errno", "status_code", "res_code",
  "error_code", "biz_code", "code", "ret", "status",
]);
const AUTHISH_KEY_RE = /login|auth|token|user|session|role/i;
const NUMERIC_RE = /^-?\d{1,4}$/;

const uniq = (xs: string[]): string[] => [...new Set(xs)].slice(0, 50);

// ---- lightweight AST helpers (same style as domSinks) ----
const property = (node: ESTree.MemberExpression): string | null =>
  !node.computed && node.property.type === "Identifier" ? node.property.name
    : node.property.type === "Literal" && typeof node.property.value === "string" ? node.property.value : null;
const pathOf = (node: ESTree.Node): string =>
  node.type === "Identifier" ? node.name
    : node.type === "MemberExpression" ? `${pathOf(node.object)}.${property(node) ?? "?"}` : "";
const within = (inner: ESTree.Node, outer: ESTree.Node): boolean =>
  !!inner.range && !!outer.range && inner.range[0] >= outer.range[0] && inner.range[1] <= outer.range[1];

const storageAccess = (call: ESTree.CallExpression): { medium: "localStorage" | "sessionStorage"; key: string; method: string } | null => {
  const path = pathOf(call.callee).replace(/^window\./, "");
  const m = /^(localStorage|sessionStorage)\.(getItem|setItem|removeItem)$/.exec(path);
  if (!m) return null;
  const a0 = call.arguments[0];
  if (!a0 || a0.type !== "Literal" || typeof a0.value !== "string") return null;
  return { medium: m[1] as "localStorage" | "sessionStorage", key: a0.value, method: m[2]! };
};

/** True when the subtree contains a redirect-to-login (router.push("/login"), location.href=".../login"...). */
const hasLoginRedirect = (root: ESTree.Node): boolean => {
  let found = false;
  walkAst(root, (n) => {
    if (found) return;
    if (n.type === "CallExpression") {
      const path = pathOf(n.callee);
      if (/(?:^|\.)(?:push|replace|navigate|assign)$/.test(path)) {
        const a0 = n.arguments[0];
        if (a0?.type === "Literal" && typeof a0.value === "string" && /login/i.test(a0.value)) found = true;
      }
    } else if (n.type === "AssignmentExpression") {
      if (/(?:^|\.)location\.href$/.test(pathOf(n.left))) {
        const right = n.right;
        if (right.type === "Literal" && typeof right.value === "string" && /login/i.test(right.value)) found = true;
      }
    }
  });
  return found;
};

interface ComparisonHit {
  field: string;
  value: string;
  isSuccess: boolean;
  file: string;
  excerpt: string;
  range: [number, number];
}

interface FileScan {
  storage: StorageCandidate[];
  comparisons: ComparisonHit[];
  evidence: GateEvidence[];
}

const scanFile = (file: string, text: string): FileScan | null => {
  const parsed = parseJavaScript(text);
  if (!parsed) return null;
  const parents = new Map<ESTree.Node, ESTree.Node | null>();
  walkAst(parsed.ast, (n, p) => parents.set(n, p));

  // nearest IfStatement whose test directly contains the node (walking up
  // only through logical/unary wrappers — that is the branch control flow)
  const enclosingIf = (node: ESTree.Node): ESTree.IfStatement | null => {
    let cur: ESTree.Node = node;
    let p = parents.get(node) ?? null;
    while (p) {
      if (p.type === "IfStatement" && within(cur, p.test)) return p;
      if (p.type === "LogicalExpression" || p.type === "UnaryExpression") { cur = p; p = parents.get(p) ?? null; continue; }
      return null;
    }
    return null;
  };

  const storage: StorageCandidate[] = [];
  const comparisons: ComparisonHit[] = [];
  const evidence: GateEvidence[] = [];
  const hits: { range: [number, number]; push: () => void }[] = [];

  walkAst(parsed.ast, (n) => {
    if (n.type === "CallExpression") {
      const access = storageAccess(n);
      if (access) {
        hits.push({
          range: n.range!,
          push: () => {
            const excerpt = text.slice(...n.range!).slice(0, 240);
            storage.push({
              medium: access.medium, key: access.key, confidence: "candidate", file, excerpt,
              basis: `direct ${access.medium}.${access.method}("${access.key}") call; medium from callee receiver`,
            });
            evidence.push({ file, kind: "storage-access", excerpt, range: n.range! });
          },
        });
      }
    } else if (n.type === "BinaryExpression" && ["===", "==", "!==", "!="].includes(n.operator)) {
      const eq = n.operator === "===" || n.operator === "==";
      let fieldSide: ESTree.MemberExpression | null = null;
      let valueSide: ESTree.Literal | null = null;
      for (const [a, b] of [[n.left, n.right], [n.right, n.left]] as const) {
        if (a.type === "MemberExpression" && b.type === "Literal") { fieldSide = a; valueSide = b; break; }
      }
      if (!fieldSide || !valueSide) return;
      const fieldName = property(fieldSide);
      const raw = valueSide.value;
      if (!fieldName || !CODE_FIELD_NAMES.has(fieldName)) return;
      if (typeof raw !== "number" && typeof raw !== "string") return;
      const value = String(raw);
      if (!NUMERIC_RE.test(value)) return;
      // Branch control flow: a comparison guarding a redirect-to-login branch
      // inverts the meaning — `===V { goto /login }` makes V a FAILURE code,
      // `!==V { goto /login }` makes V the SUCCESS code.
      const iff = enclosingIf(n);
      const loginBranch = !!iff && hasLoginRedirect(iff.consequent);
      const isSuccess = loginBranch ? !eq : eq;
      hits.push({
        range: n.range!,
        push: () => {
          const excerpt = text.slice(...n.range!).slice(0, 240);
          comparisons.push({ field: fieldName, value, isSuccess, file, excerpt, range: n.range! });
          evidence.push({ file, kind: "code-comparison", excerpt, range: n.range! });
        },
      });
    }
  });
  // position order within the file
  hits.sort((a, b) => a.range[0] - b.range[0]);
  for (const h of hits) h.push();
  return { storage, comparisons, evidence };
};

export const analyzeGates = async (input: { jsDir: string; outputRoot: string }): Promise<GateFindings> => {
  await mkdir(input.outputRoot, { recursive: true });
  let files: FileText[] = [];
  try {
    const names = (await readdir(input.jsDir)).filter((n) => n.endsWith(".js")).slice(0, 400);
    files = await Promise.all(
      names.map(async (n) => {
        try { return { file: n, text: await readFile(join(input.jsDir, n), "utf8") }; }
        catch { return { file: n, text: "" }; }
      }),
    );
  } catch {
    files = [];
  }
  const all = files.map((f) => f.text).join("\n");

  // ---- AST scan (storage medium + branch-classified code comparisons) ----
  const storageCandidates: StorageCandidate[] = [];
  const comparisons: ComparisonHit[] = [];
  const evidence: GateEvidence[] = [];
  for (const f of files) {
    if (!f.text) continue;
    const scan = scanFile(f.file, f.text);
    if (!scan) continue;
    storageCandidates.push(...scan.storage);
    comparisons.push(...scan.comparisons);
    evidence.push(...scan.evidence);
  }
  if (storageCandidates.length > 200) storageCandidates.length = 200;
  if (comparisons.length > 500) comparisons.length = 500;
  if (evidence.length > 500) evidence.length = 500;

  // regex-derived redirect triggers also become evidence (provenance)
  for (const m of all.matchAll(REDIRECT_RE)) {
    evidence.push({ file: "corpus", kind: "redirect-trigger", excerpt: m[0].slice(0, 100), range: [m.index ?? 0, (m.index ?? 0) + m[0].length] });
  }

  // ---- A1 render gate ----
  const storageKeys = uniq(storageCandidates.map((c) => c.key));
  const cookieKeys = uniq([...all.matchAll(COOKIE_KEY_RE)].map((m) => m[1]!));
  const loginStateExpressions = uniq([...all.matchAll(LOGIN_STATE_RE)].map((m) => m[0]));
  const decodeChain: GateFindings["renderGate"]["decodeChain"] = [];
  if (all.length > 0) {
    decodeChain.push("plain");
    if (/JSON\.parse\(/.test(all)) decodeChain.push("json");
    if (/atob\(/.test(all)) decodeChain.push("b64json");
    if (/\bjwt\b|\bBearer\b/i.test(all)) decodeChain.push("jwt");
  }

  // ---- A2 interceptor gate (success/failure split by branch control flow) ----
  const codeFields = uniq(comparisons.map((c) => c.field));
  const successValues = uniq(comparisons.filter((c) => c.isSuccess).map((c) => c.value));
  const failureValues = uniq(comparisons.filter((c) => !c.isSuccess).map((c) => c.value));
  const redirectTriggers = uniq([...all.matchAll(REDIRECT_RE)].map((m) => m[0].slice(0, 100)));
  const fieldsWithSuccess = new Set(comparisons.filter((c) => c.isSuccess).map((c) => c.field));

  // ---- A3 content gate ----
  const permissionApiPaths = uniq([...all.matchAll(PERM_API_RE)].map((m) => m[1]!)).filter((p) => p.length > 3);
  const menuApiPaths = uniq([...all.matchAll(MENU_API_RE)].map((m) => m[1]!)).filter((p) => p.length > 3);
  const authMapObjects = uniq([...all.matchAll(AUTHMAP_RE)].map((m) => m[0]));
  const routeMapObjects = uniq([...all.matchAll(ROUTEMAP_RE)].map((m) => m[0]));

  // ---- suggested HookConfig ----
  // Only ACTUAL localStorage keys become localStorage patches; sessionStorage
  // hints stay candidates (wrong medium would write a dead patch).
  const lsPatch: Record<string, string> = {};
  for (const c of storageCandidates) {
    if (c.medium !== "localStorage" || !AUTHISH_KEY_RE.test(c.key)) continue;
    if (Object.keys(lsPatch).length >= 8) break;
    lsPatch[c.key] = "1";
  }
  const cookiePatch: { name: string; value: string }[] = cookieKeys
    .filter((k) => AUTHISH_KEY_RE.test(k))
    .slice(0, 6)
    .map((k) => ({ name: k, value: "1" }));
  // Neutralize fields only for code fields with POSITIVE success evidence —
  // a field whose only observed value is a failure code (401 → /login) must
  // not become an executable gate patch.
  const fields = codeFields.filter((f) => fieldsWithSuccess.has(f)).slice(0, 6);
  const success = successValues.find((v) => v === "0") ?? successValues[0] ?? "0";
  // Per-field success values: different code fields may use different success
  // codes (code:0 vs ret:200) — one global value would patch the wrong field.
  const fieldSuccess: Record<string, string> = {};
  for (const c of comparisons) if (c.isSuccess && fields.includes(c.field)) fieldSuccess[c.field] ??= c.value;
  const stubs: { match: string; body: unknown }[] = [];
  for (const p of [...permissionApiPaths.slice(0, 2), ...menuApiPaths.slice(0, 2)]) {
    stubs.push({ match: p.replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === "/" ? "\\/" : `\\${c}`)), body: { code: Number(success), data: { permissions: ["*"], menus: [] } } });
  }

  const result: GateFindings = {
    renderGate: { storageKeys, cookieKeys, loginStateExpressions, decodeChain },
    interceptorGate: { codeFields, successValues, failureValues, redirectTriggers },
    contentGate: { permissionApiPaths, menuApiPaths, authMapObjects, routeMapObjects },
    suggestedConfig: { localStorage: lsPatch, cookies: cookiePatch, neutralize: { fields, success, ...(Object.keys(fieldSuccess).length ? { fieldSuccess } : {}) }, stubs },
    storageCandidates,
    evidence,
  };
  await writeFile(join(input.outputRoot, "gates_report.json"), JSON.stringify(result, null, 2));
  return result;
};
