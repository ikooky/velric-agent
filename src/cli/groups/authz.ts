import type { Ctx } from "../shared.js";

/** 授权 — 越权与访问控制 */
export const AuthzHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "auth-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [endpointsFile, dir] = positional;
  if (!endpointsFile || !dir) {
    console.error("usage: auth-probe <api_merged.txt> <outdir> [--cookie STR]");
    return 2;
  }
  const { probeAuth } = await import("../../domain/authProbe.js");
  out(await probeAuth({ endpointsFile, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "idor-prescreen": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [mergedFile, dir] = positional;
  if (!mergedFile || !dir) {
    console.error("usage: idor-prescreen <params_merged.json> <outdir> [--cookie STR]");
    return 2;
  }
  const { prescreenIdor } = await import("../../domain/authProbe.js");
  out(await prescreenIdor({ mergedFile, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "idor-deep": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const endpoints = await jarrObj<{ method: string; path: string; fields: { name: string; in: string }[] }>(flags, "endpoints");
  if (!dir || !endpoints) {
    console.error("usage: idor-deep <outdir> --endpoints[-file] '[{\"method\":\"GET\",\"path\":\"/api/x\",\"fields\":[{\"name\":\"id\",\"in\":\"query\"}]}]' [--base URL] [--ids a,b] [--max-targets N] [--write] [--write-payload JSON] [--write-method PATCH]");
    return 2;
  }
  const { probeIdorDeep } = await import("../../domain/idorDeep.js");
  out(await probeIdorDeep({
    endpoints, outputRoot: dir,
    baseUrl: typeof flags.base === "string" ? flags.base : undefined,
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    writeMode: flags["write"] === true,
    writePayload: await jobj<Record<string, unknown>>(flags, "write-payload"),
    writeMethod: typeof flags["write-method"] === "string" ? flags["write-method"] : undefined,
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxTargets: num(flags["max-targets"]),
    objectIds: jarr(flags, "ids"),
  }));
  return 0;
  },
  "authz-replay": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [recordRoot, dir] = positional;
  const roles = await jobj<Record<string, string>>(flags, "roles");
  if (!recordRoot || !dir || !roles) {
    console.error("usage: authz-replay <recordRoot> <outdir> --roles[-file] '{\"admin\":\"Cookie: ..\"}' [--role-headers-file JSON] [--markers-file JSON] [--ids a,b] [--methods a,b] [--anonymous] [--read-only] [--apply]");
    return 2;
  }
  const { replayAuthz } = await import("../../domain/authzReplay.js");
  const r = await replayAuthz({
    recordRoot, outputRoot: dir, roles,
    roleHeaders: await jobj<Record<string, Record<string, string>>>(flags, "role-headers"),
    markers: await jobj<Record<string, string[]>>(flags, "markers"),
    anonymous: flags.anonymous === true,
    exchangeIds: jarr(flags, "ids"),
    methods: jarr(flags, "methods"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxExchanges: num(flags.max),
    denyFingerprints: jarr(flags, "deny-fingerprints"),
    readOnly: flags["read-only"] === true,
    apply: flags.apply === true,
  });
  out({ replayed: r.replayed, bypassed: r.bypassed.map((c) => ({ url: c.url, role: c.role, note: c.note })), enforced: r.enforced.length, unknown: r.unknown.length, artifacts: r.artifacts });
  return 0;
  },
  "role-matrix": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [reconRoot, dir] = positional;
  const roles = await jobj<Record<string, string>>(flags, "roles");
  if (!reconRoot || !dir || !roles) {
    console.error("usage: role-matrix <reconRoot> <outdir> --roles[-file] '{\"admin\":\"cookie=..\"}' [--max-endpoints N]");
    return 2;
  }
  const { probeRoleMatrix } = await import("../../domain/roleMatrix.js");
  out(await probeRoleMatrix({
    reconRoot, outputRoot: dir, roles,
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxEndpoints: num(flags["max-endpoints"]),
  }));
  return 0;
  },
  "role-escalate": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: role-escalate <url> <outdir> [--method POST] [--body-template '{}'] [--fields a,b] [--uniquify]"); return 2; }
  const { probeRoleEscalation } = await import("../../domain/roleEscalate.js");
  const strList3 = (v: string | boolean | undefined): string[] | undefined => typeof v === "string" && v.length > 0 ? v.split(",").map(x => x.trim()).filter(Boolean) : undefined;
  const r = await probeRoleEscalation({ url, method: typeof flags.method === "string" ? flags.method : undefined, bodyTemplate: typeof flags["body-template"] === "string" ? flags["body-template"] : undefined, fields: strList3(flags.fields), outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), uniquify: flags.uniquify === true });
  out({ probed: r.probed, findings: r.findings.length, detail: r.findings.slice(0, 15), artifacts: r.artifacts });
  return 0;
  },
  "mass-assign": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [recordRoot, dir] = positional;
  if (!recordRoot || !dir) {
    console.error("usage: mass-assign <recordRoot> <outdir> [--credential STR] [--ids a,b] [--fields a,b] [--apply] [--max N]");
    return 2;
  }
  const { probeMassAssign } = await import("../../domain/massAssign.js");
  const r = await probeMassAssign({
    recordRoot, outputRoot: dir,
    credential: typeof flags.credential === "string" ? flags.credential : undefined,
    exchangeIds: jarr(flags, "ids"),
    fields: jarr(flags, "fields"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxExchanges: num(flags.max),
    apply: flags.apply === true,
  });
  out({ probed: r.probed, sinks: r.sinks.map((o) => ({ url: o.url, field: o.field, verdict: o.verdict, note: o.note })), outcomes: r.outcomes, artifacts: r.artifacts });
  return 0;
  },
  "api-version": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: api-version <versioned-api-url> <outdir> [--bearer T] [--prefixes a,b]"); return 2; }
  const { probeApiVersion } = await import("../../domain/apiVersion.js");
  const strListV = (v: string | boolean | undefined): string[] | undefined => typeof v === "string" && v.length > 0 ? v.split(",").map(x => x.trim()).filter(Boolean) : undefined;
  const r = await probeApiVersion({ url, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), extraPrefixes: strListV(flags.prefixes), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, leaks: r.leaks.length, detail: r.leaks.slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "header-bypass": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const urls = jarr(flags, "urls");
  if (!dir || !urls) {
    console.error("usage: header-bypass <outdir> --urls a,b [--max N]");
    return 2;
  }
  const { probeHeaderBypass } = await import("../../domain/headerBypass.js");
  out(await probeHeaderBypass({
    urls, outputRoot: dir,
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxUrls: num(flags.max),
  }));
  return 0;
  },
  "verb-matrix": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const urls = jarr(flags, "urls");
  if (!dir || !urls) {
    console.error("usage: verb-matrix <outdir> --urls a,b [--max N]");
    return 2;
  }
  const { probeVerbMatrix } = await import("../../domain/verbMatrix.js");
  out(await probeVerbMatrix({
    urls, outputRoot: dir,
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxUrls: num(flags.max),
  }));
  return 0;
  },
  "graphql-authz": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [endpoint, schemaFile, dir] = positional;
  if (!endpoint || !schemaFile || !dir) {
    console.error("usage: graphql-authz <endpoint> <schemaFile> <outdir> [--token STR] [--max-fields N]");
    return 2;
  }
  const { probeGraphqlAuthz } = await import("../../domain/graphqlAuthz.js");
  out(await probeGraphqlAuthz({
    endpoint, schemaFile, outputRoot: dir,
    token: typeof flags.token === "string" ? flags.token : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxFields: num(flags["max-fields"]),
  }));
  return 0;
  },

  "path-auth-bypass": async (ctx) => {
    const { positional, flags, out, num, jobj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: path-auth-bypass <protectedUrl> <outdir> [--cookie C]"); return 2; }
  const { probePathBypass } = await import("../../domain/pathAuthBypass.js");
  const r = await probePathBypass({ protectedUrl: url, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ denied: r.denied, bypassed: r.bypassed, variants: r.variants, artifacts: r.artifacts });
  return r.bypassed.length ? 0 : 1;
  },

  "signed-url": async (ctx) => {
    const { positional, flags, out, num, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: signed-url <signedUrl> <outdir>"); return 2; }
  const { probeSignedUrl } = await import("../../domain/signedUrl.js");
  const r = await probeSignedUrl({ url, outputRoot: dir, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ signed: r.signed, exploitable: r.exploitable, cases: r.cases, artifacts: r.artifacts });
  return r.exploitable ? 0 : 1;
  },
};
