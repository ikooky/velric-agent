import { readFile } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Client-side auth-gate reverse engineering (api-recon Phase 2, reference
 *  A1/A2/A3): static grep recipes over the harvested JS corpus that locate
 *  the three gates every protected SPA puts in front of its API surface.
 *
 *  A1 render gate      — how the app decides "logged in"
 *  A2 interceptor gate — which response code field triggers /login redirect
 *  A3 content gate     — where menus/permissions come from
 *
 *  Output feeds HookConfig (cookies/localStorage keys, neutralize fields,
 *  stub matches) — the deterministic replacement for the manual grep pass. */

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
    neutralize: { fields: string[]; success: number | string };
    stubs: { match: string; body: unknown }[];
  };
}

interface FileText {
  file: string;
  text: string;
}

const STORAGE_KEY_RE = /(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(\s*["']([^"']+)["']/g;
const COOKIE_KEY_RE = /(?:Cookies?|cookie)\.(?:get|load|set)\(\s*["']([^"']+)["']/g;
const LOGIN_STATE_RE = /(?:isLogin|isAuthenticated|loggedIn|hasLogin|requireAuth|hasPermission|checkAuth)\s*[=!]==?\s*(?:true|"1"|'1'|1)/g;
const CODE_FIELD_RE = /(?:response_code|errcode|errno|\bcode\b|\bret\b|\bstatus\b)\s*[=!]==?\s*["']?-?\d{1,4}["']?/g;
const REDIRECT_RE = /(?:location\.href|router\.(?:push|replace)|navigate)\s*\(\s*["'][^"']*login[^"']*["']/gi;
const PERM_API_RE = /["'](\/[^"']*(?:permission|perm|role|acl|resource)[^"']*)["']/gi;
const MENU_API_RE = /["'](\/[^"']*(?:menu|menus|nav|sidebar)[^"']*)["']/gi;
const AUTHMAP_RE = /(?:userRouteAuth|getResultTree|hasPermission|checkAuth|authList)\s*=/g;
const ROUTEMAP_RE = /(?:routeMap|routeLink|menuList)\s*=/g;
const DECODE_JWT_RE = /atob\(|jwt|decode|JSON\.parse\(/i;

const uniq = (xs: string[]): string[] => [...new Set(xs)].slice(0, 50);

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

  // ---- A1 render gate ----
  const storageKeys = uniq([...all.matchAll(STORAGE_KEY_RE)].map((m) => m[1]!));
  const cookieKeys = uniq([...all.matchAll(COOKIE_KEY_RE)].map((m) => m[1]!));
  const loginStateExpressions = uniq([...all.matchAll(LOGIN_STATE_RE)].map((m) => m[0]));
  const decodeChain: GateFindings["renderGate"]["decodeChain"] = [];
  if (all.length > 0) {
    decodeChain.push("plain");
    if (/JSON\.parse\(/.test(all)) decodeChain.push("json");
    if (/atob\(/.test(all)) decodeChain.push("b64json");
    if (/\bjwt\b|\bBearer\b/i.test(all)) decodeChain.push("jwt");
  }

  // ---- A2 interceptor gate ----
  const codeFields = uniq(
    [...all.matchAll(CODE_FIELD_RE)]
      .map((m) => m[0].split(/[=!]=/)[0]!.trim().replace(/^["']|["']$/g, ""))
      .filter((f) => f.length > 1 && f.length < 24 && !/^(?:if|for|while|this|window)$/.test(f)),
  );
  const successValues = uniq(
    [...all.matchAll(CODE_FIELD_RE)]
      // Strip the comparison operator chain (===, !==, ==, =) before the
      // value — split(/[=!]=/) leaves a leading "=0" that fails validation
      // and silently drops the dominant minified-bundle form.
      .map((m) => m[0].replace(/^[^=]*[=!]==?\s*/, "").trim().replace(/^["']|["']$/g, ""))
      .filter((v) => /^-?\d{1,4}$/.test(v)),
  );
  const redirectTriggers = uniq([...all.matchAll(REDIRECT_RE)].map((m) => m[0].slice(0, 100)));

  // ---- A3 content gate ----
  const permissionApiPaths = uniq([...all.matchAll(PERM_API_RE)].map((m) => m[1]!)).filter((p) => p.length > 3);
  const menuApiPaths = uniq([...all.matchAll(MENU_API_RE)].map((m) => m[1]!)).filter((p) => p.length > 3);
  const authMapObjects = uniq([...all.matchAll(AUTHMAP_RE)].map((m) => m[0]));
  const routeMapObjects = uniq([...all.matchAll(ROUTEMAP_RE)].map((m) => m[0]));

  // ---- suggested HookConfig ----
  const lsPatch: Record<string, string> = {};
  for (const k of storageKeys.filter((k) => /login|auth|token|user|session|role/i.test(k)).slice(0, 8)) {
    lsPatch[k] = "1";
  }
  const cookiePatch: { name: string; value: string }[] = cookieKeys
    .filter((k) => /login|auth|token|session|user/i.test(k))
    .slice(0, 6)
    .map((k) => ({ name: k, value: "1" }));
  const fields = codeFields.filter((f) => /code|errno|ret|status/i.test(f)).slice(0, 6);
  if (fields.length === 0) fields.push("code");
  const success = (successValues.find((v) => v === "0") ?? successValues[0] ?? "0");
  const stubs: { match: string; body: unknown }[] = [];
  for (const p of [...permissionApiPaths.slice(0, 2), ...menuApiPaths.slice(0, 2)]) {
    stubs.push({ match: p.replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === "/" ? "\\/" : `\\${c}`)), body: { code: Number(success), data: { permissions: ["*"], menus: [] } } });
  }

  const result: GateFindings = {
    renderGate: { storageKeys, cookieKeys, loginStateExpressions, decodeChain },
    interceptorGate: { codeFields, successValues, redirectTriggers },
    contentGate: { permissionApiPaths, menuApiPaths, authMapObjects, routeMapObjects },
    suggestedConfig: { localStorage: lsPatch, cookies: cookiePatch, neutralize: { fields, success }, stubs },
  };
  await writeFile(join(input.outputRoot, "gates_report.json"), JSON.stringify(result, null, 2));
  return result;
};
