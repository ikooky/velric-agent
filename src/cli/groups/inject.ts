import type { Ctx } from "../shared.js";

/** 注入 — 语法与参数 */
export const InjectHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "sqli-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: sqli-probe <url> <outdir> --param q [--in query|body] [--body-template '{}'] [--auth-bypass] [--bearer T]"); return 2; }
  const { probeSqli } = await import("../../domain/sqliProbe.js");
  const r = await probeSqli({ url, param: String(flags.param ?? "q"), in: typeof flags.in === "string" ? (flags.in === "body" ? "body" : "query") : "query", bodyTemplate: typeof flags["body-template"] === "string" ? flags["body-template"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), authBypass: flags["auth-bypass"] === true });
  out({ probed: r.probed, confirmed: r.confirmed.length, leads: r.leads.length, detail: [...r.confirmed, ...r.leads].slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "nosqli-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: nosqli-probe <url> <outdir> --param id [--in body] [--method PATCH] [--body-template T] [--bearer T]"); return 2; }
  const { probeNosqli } = await import("../../domain/nosqliProbe.js");
  const r = await probeNosqli({ url, param: String(flags.param ?? "id"), in: typeof flags.in === "string" ? (flags.in === "body" ? "body" : "query") : "query", method: typeof flags.method === "string" ? flags.method : undefined, bodyTemplate: typeof flags["body-template"] === "string" ? flags["body-template"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, confirmed: r.confirmed.length, leads: r.leads.length, detail: [...r.confirmed, ...r.leads].slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "ldap-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: ldap-probe <url> <outdir> --param uid [--in body] [--body-template T]"); return 2; }
  const { probeLdap } = await import("../../domain/ldapProbe.js");
  const r = await probeLdap({ url, param: String(flags.param ?? "uid"), in: typeof flags.in === "string" ? (flags.in === "body" ? "body" : "query") : "query", method: typeof flags.method === "string" ? flags.method : undefined, bodyTemplate: typeof flags["body-template"] === "string" ? flags["body-template"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, confirmed: r.confirmed.length, leads: r.leads.length, detail: [...r.confirmed, ...r.leads].slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "ssti-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: ssti-probe <url> <outdir> --param q [--in query|body] [--body-template T] [--bearer T]"); return 2; }
  const { probeSsti } = await import("../../domain/sstiProbe.js");
  const r = await probeSsti({ url, param: String(flags.param ?? "q"), in: typeof flags.in === "string" ? (flags.in === "body" ? "body" : "query") : "query", method: typeof flags.method === "string" ? flags.method : undefined, bodyTemplate: typeof flags["body-template"] === "string" ? flags["body-template"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, confirmed: r.confirmed.length, detail: r.confirmed, artifacts: r.artifacts });
  return 0;
  },
  "proto-pollute": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: proto-pollute <url> <outdir> [--method POST] [--body-template '{}']"); return 2; }
  const { probePrototype } = await import("../../domain/protoPollute.js");
  const r = await probePrototype({ url, method: typeof flags.method === "string" ? flags.method : undefined, bodyTemplate: typeof flags["body-template"] === "string" ? flags["body-template"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, findings: r.findings.length, detail: r.findings, artifacts: r.artifacts });
  return 0;
  },
  "hpp-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: hpp-probe <url> <outdir> --params a,b [--expected V]"); return 2; }
  const { probeHpp } = await import("../../domain/hppProbe.js");
  const strList = (v: string | boolean | undefined): string[] | undefined => typeof v === "string" && v.length > 0 ? v.split(",").map(x => x.trim()).filter(Boolean) : undefined;
  const r = await probeHpp({ baseUrl: url, outputRoot: dir, params: strList(flags.params) ?? ["id", "q", "page", "redirect", "url"], expectedValue: typeof flags.expected === "string" ? flags.expected : undefined, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, findings: r.findings.length, detail: r.findings.slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "redirect-traverse": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: redirect-traverse <url> <outdir> [--params a,b] [--trav-path]"); return 2; }
  const { probeRedirectTraversal } = await import("../../domain/redirectTraverse.js");
  const strList2 = (v: string | boolean | undefined): string[] | undefined => typeof v === "string" && v.length > 0 ? v.split(",").map(x => x.trim()).filter(Boolean) : undefined;
  const r = await probeRedirectTraversal({ baseUrl: url, params: strList2(flags.params), pathTraversal: flags["trav-path"] === true, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ redirectProbed: r.redirectProbed, externalRedirects: r.redirectFindings.length, traversalProbed: r.traversalProbed, traversalHits: r.traversalFindings.length, redirectFindings: r.redirectFindings.slice(0, 10), artifacts: r.artifacts });
  return 0;
  },

  "deser-surface": async (ctx) => {
    const { positional, flags, out, num, jarr, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: deser-surface <url> <outdir> [--params a,b] [--cookie-name C]"); return 2; }
  const { probeDeser } = await import("../../domain/deserSurface.js");
  const r = await probeDeser({ url, outputRoot: dir, params: jarr(flags, "params"), cookieName: typeof flags["cookie-name"] === "string" ? flags["cookie-name"] : undefined, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ passive: r.passive, viewState: r.viewState, exploitable: r.exploitable, probes: r.probes, artifacts: r.artifacts });
  return r.exploitable.length ? 0 : 1;
  },
};
