import type { Ctx } from "../shared.js";
import { mergeParamSamples } from "../../application/paramMerge.js";
import { buildPermissionTree } from "../../application/permTreeService.js";
import { captureRuntime } from "../../application/runtime.js";
import { DEFAULT_HOOK_CONFIG } from "../../domain/preload.js";

/** 运行时 — 浏览器与协议 */
export const RuntimeHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "runtime": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [base, dir] = positional;
  if (!base || !dir) {
    console.error(
      "usage: runtime <url> <outdir> [--chromium PATH] [--routes /a,/b] [--wait MS] [--per-route MS] [--route-timeout MS] [--api-pattern RE] [--headless false] [--proxy URL]",
    );
    return 2;
  }
  const strList = (v: string | boolean | undefined): string[] | undefined =>
    typeof v === "string" && v.trim() !== ""
      ? v.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined;
  out(
    await captureRuntime({
      baseUrl: base,
      outputRoot: dir,
      chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
      proxy: await resolveProxy(flags),
      routes: strList(flags.routes),
      maxRoutes: num(flags["max-routes"]),
      waitMs: num(flags.wait),
      perRouteMs: num(flags["per-route"]),
      routeTimeoutMs: num(flags["route-timeout"]),
      headless: flags.headless === "false" ? false : undefined,
      hook: typeof flags["api-pattern"] === "string"
        ? { ...DEFAULT_HOOK_CONFIG, apiPattern: flags["api-pattern"] }
        : undefined,
    }),
  );
  return 0;
  },
  "session-crawl": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [baseUrl, loginUrl, user, pass, dir] = positional;
  if (!baseUrl || !loginUrl || !user || !pass || !dir) {
    console.error("usage: session-crawl <baseUrl> <loginUrl> <user> <pass> <outdir> [--login-mode form|json] [--user-field F] [--pass-field F] [--endpoints a,b] [--max-pages N]");
    return 2;
  }
  const { crawlSession } = await import("../../domain/sessionCrawl.js");
  const lm = flags["login-mode"];
  out(await crawlSession({
    baseUrl, loginUrl, username: user, password: pass, outputRoot: dir,
    loginMode: lm === "form" || lm === "json" ? lm : undefined,
    usernameField: typeof flags["user-field"] === "string" ? flags["user-field"] : undefined,
    passwordField: typeof flags["pass-field"] === "string" ? flags["pass-field"] : undefined,
    endpoints: jarr(flags, "endpoints"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxPages: num(flags["max-pages"]),
    maxRelogins: num(flags["max-relogins"]),
    headers: await jobj<Record<string, string>>(flags, "headers"),
    loggedInRegex: typeof flags["logged-in"] === "string" ? flags["logged-in"] : undefined,
    loggedOutRegex: typeof flags["logged-out"] === "string" ? flags["logged-out"] : undefined,
  }));
  return 0;
  },
  "perm-tree": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [jsDir, dir] = positional;
  if (!jsDir || !dir) {
    console.error("usage: perm-tree <jsdir> <outdir> [--role NAME]");
    return 2;
  }
  out(
    await buildPermissionTree({
      jsDir,
      outputRoot: dir,
      role: typeof flags.role === "string" ? flags.role : undefined,
    }),
  );
  return 0;
  },
  "merge-params": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [samples, dir] = positional;
  if (!samples || !dir) {
    console.error("usage: merge-params <samples.json> <outdir>");
    return 2;
  }
  out(await mergeParamSamples({ samplesFile: samples, outputRoot: dir }));
  return 0;
  },
  "ws-schema": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [runtimeFile, dir] = positional;
  if (!runtimeFile || !dir) {
    console.error("usage: ws-schema <runtime_api.json> <outdir>");
    return 2;
  }
  const { extractWsSchema } = await import("../../domain/wsSchema.js");
  out(await extractWsSchema({ runtimeFile, outputRoot: dir }));
  return 0;
  },
  "proto-decode": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [data, dir] = positional;
  if (!data || !dir || (flags.enc !== undefined && flags.enc !== "hex" && flags.enc !== "base64")) { console.error("usage: proto-decode <hex|base64> <outdir> [--enc hex|base64]"); return 2; }
  const { decodeProtoHeuristic } = await import("../../domain/protoDecode.js");
  out(await decodeProtoHeuristic({ data, encoding: (flags.enc === "hex" ? "hex" : "base64") as "hex" | "base64", outputRoot: dir }));
  return 0;
  },
  "ws-origin-check": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [u, dir] = positional;
  if (!u || !dir) { console.error("usage: ws-origin-check <wsUrl> <outdir>"); return 2; }
  const { probeWsOrigin } = await import("../../domain/wsOrigin.js");
  out(await probeWsOrigin({ url: u, outputRoot: dir }));
  return 0;
  },
};
