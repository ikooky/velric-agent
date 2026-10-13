import { writeArtifact } from "../adapters/artifacts.js";
import { readJsCorpus } from "./harvest.js";
import {
  DEFAULT_PERM_HEURISTICS,
  buildGenericPermTree,
  buildPermTree,
  extractGenericRbac,
  extractRouteMap,
  flatCodes,
  parseUserRouteAuth,
  type PermTreeHeuristics,
  type PermTreeNode,
} from "../domain/permTree.js";
export interface PermTreeInput {
  readonly jsDir: string;
  readonly outputRoot: string;
  readonly role?: string;
  readonly roots?: string[];
  readonly prefixParent?: Record<string, string>;
  readonly extraParent?: Record<string, string>;
}

export interface PermTreeResult {
  readonly authSourceFile: string | null;
  readonly entries: number;
  readonly codes: number;
  readonly treeRoots: number;
  readonly tree: PermTreeNode[];
  readonly artifacts: { path: string; bytes: number }[];
  readonly mode?: "generic-rbac";
}

/**
 * Permission-tree reconstruction (port of build_perm_tree.py): parse
 * userRouteAuth, resolve webpack aliases via route_map, infer hierarchy from
 * code prefixes, emit permissive menu/permission stubs.
 */
export const buildPermissionTree = async (
  input: PermTreeInput,
): Promise<PermTreeResult> => {
  const corpus = await readJsCorpus(input.jsDir);
  if (corpus.length === 0) {
    throw {
      code: "no_js_corpus",
      message: `no .js files found under ${input.jsDir}`,
      remediation: "run harvest_static first and pass its js/ directory",
    };
  }
  const { routeMap, source: routeMapSource } = extractRouteMap(corpus);

  // find the file that actually contains userRouteAuth
  let authFile: { path: string; text: string } | null = null;
  for (const f of corpus) {
    if (!f.text.includes("userRouteAuth")) continue;
    if (authFile === null || f.text.length > authFile.text.length) authFile = f;
  }
  // Generic fallback: no userRouteAuth in the corpus — mine generic RBAC
  // signals (hasPermi/hasRole/permission literals, route roles guards)
  // instead of failing hard.
  if (authFile === null) {
    const rbac = extractGenericRbac(corpus);
    if (rbac.permissionCodes.length === 0 && rbac.routeRoles.length === 0) {
      throw {
        code: "auth_module_not_found",
        message:
          "neither userRouteAuth nor generic RBAC markers (hasPermi/hasRole/permission) found in the JS corpus",
        remediation: "run harvest_static first; the target may not embed auth metadata client-side",
      };
    }
    const tree = buildGenericPermTree(rbac.permissionCodes);
    const role = input.role ?? "SUPER_ADMIN";
    const permAll = { response_code: 0, verbose_msg: "ok", data: tree };
    const rolePerm = {
      response_code: 0,
      verbose_msg: "ok",
      data: { role_type: role, permissions: rbac.permissionCodes },
    };
    const artifacts: { path: string; bytes: number }[] = [];
    artifacts.push(
      await writeArtifact(input.outputRoot, "perm_codes_generic.txt", rbac.permissionCodes.join("\n")),
    );
    if (rbac.routeRoles.length > 0) {
      artifacts.push(
        await writeArtifact(input.outputRoot, "route_roles.json", JSON.stringify(rbac.routeRoles, null, 2)),
      );
    }
    artifacts.push(
      await writeArtifact(input.outputRoot, "permissions_tree.json", JSON.stringify(tree, null, 2)),
    );
    artifacts.push(
      await writeArtifact(input.outputRoot, "permissions_all_stub.json", JSON.stringify(permAll, null, 2)),
    );
    artifacts.push(
      await writeArtifact(input.outputRoot, "role_permissions_stub.json", JSON.stringify(rolePerm, null, 2)),
    );
    return {
      authSourceFile: rbac.source,
      entries: rbac.permissionCodes.length,
      codes: rbac.permissionCodes.length,
      treeRoots: tree.length,
      tree,
      artifacts,
      mode: "generic-rbac" as const,
    };
  }
  const entries = parseUserRouteAuth(authFile.text, routeMap);
  if (Object.keys(entries).length === 0) {
    throw {
      code: "auth_parse_failed",
      message: `userRouteAuth present in ${authFile.path} but no entries parsed`,
      remediation: "adjust heuristics (roots/prefixParent) or inspect the chunk",
    };
  }

  const heuristics: PermTreeHeuristics = {
    roots: input.roots ?? DEFAULT_PERM_HEURISTICS.roots,
    prefixParent: input.prefixParent ?? DEFAULT_PERM_HEURISTICS.prefixParent,
    extraParent: input.extraParent ?? DEFAULT_PERM_HEURISTICS.extraParent,
  };
  const tree = buildPermTree(entries, heuristics);
  const allCodes = [
    ...new Set([
      ...flatCodes(tree),
      ...Object.values(entries).flatMap((e) => e.control),
    ]),
  ].sort();

  const role = input.role ?? "SUPER_ADMIN";
  const permAll = { response_code: 0, verbose_msg: "ok", data: tree };
  const rolePerm = {
    response_code: 0,
    verbose_msg: "ok",
    data: { role_type: role, permissions: allCodes },
  };

  const artifacts: { path: string; bytes: number }[] = [];
  artifacts.push(
    await writeArtifact(input.outputRoot, "route_map.json", JSON.stringify(routeMap, null, 2)),
  );
  artifacts.push(
    await writeArtifact(input.outputRoot, "userRouteAuth.json", JSON.stringify(entries, null, 2)),
  );
  artifacts.push(
    await writeArtifact(input.outputRoot, "permissions_tree.json", JSON.stringify(tree, null, 2)),
  );
  artifacts.push(
    await writeArtifact(input.outputRoot, "perm_codes_all.txt", allCodes.join("\n")),
  );
  artifacts.push(
    await writeArtifact(input.outputRoot, "permissions_all_stub.json", JSON.stringify(permAll, null, 2)),
  );
  artifacts.push(
    await writeArtifact(input.outputRoot, "role_permissions_stub.json", JSON.stringify(rolePerm, null, 2)),
  );

  return {
    authSourceFile: authFile.path,
    entries: Object.keys(entries).length,
    codes: allCodes.length,
    treeRoots: tree.length,
    tree,
    artifacts,
    ...(routeMapSource ? { routeMapSource } : {}),
  } as PermTreeResult;
};