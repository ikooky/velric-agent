import type { Ctx } from "../shared.js";

/** 业务逻辑 — 值域与竞争 */
export const LogicHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "value-abuse": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: value-abuse <url> <outdir> --body-template '{\"quantity\":1}' [--fields a,b] [--verify-url U] [--bearer T] [--cookie C]"); return 2; }
  const { probeValueAbuse } = await import("../../domain/valueAbuse.js");
  const r = await probeValueAbuse({ url, bodyTemplate: String(flags["body-template"] ?? "{}"), fields: typeof flags.fields === "string" ? flags.fields.split(",") : undefined, verifyUrl: typeof flags["verify-url"] === "string" ? flags["verify-url"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, confirmed: r.confirmed.length, leads: r.leads.length, detail: [...r.confirmed.slice(0, 10), ...r.leads.slice(0, 10)], artifacts: r.artifacts });
  return 0;
  },
  "race-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: race-probe <url> <outdir> [--method POST] [--body JSON] [--verify-url U] [--concurrency N] [--rounds N] [--bearer T]"); return 2; }
  const { probeRace } = await import("../../domain/raceProbe.js");
  const r = await probeRace({ url, method: typeof flags.method === "string" ? flags.method : undefined, body: typeof flags.body === "string" ? flags.body : undefined, verifyUrl: typeof flags["verify-url"] === "string" ? flags["verify-url"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), concurrency: num(flags.concurrency), rounds: num(flags.rounds) });
  out({ fired: r.fired, admitted: r.admitted, rejected: r.rejected, distinctBodies: r.distinctSuccessBodies, raceSuspected: r.raceSuspected, evidence: r.evidence, rounds: r.rounds, stateChanged: r.verifyBefore !== r.verifyAfter, artifacts: r.artifacts });
  return 0;
  },
  "cache-deceive": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: cache-deceive <baseUrl> <outdir> [--private-path /api/me]"); return 2; }
  const { probeCache } = await import("../../domain/cacheDeceive.js");
  const r = await probeCache({ baseUrl: url, privatePath: typeof flags["private-path"] === "string" ? flags["private-path"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, deceptionSuspects: r.deceptionSuspects.length, poisonSurface: r.poisonSurface, artifacts: r.artifacts });
  return 0;
  },
  "host-poison": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: host-poison <url> <outdir> [--canary-host H]"); return 2; }
  const { probeHostPoison } = await import("../../domain/hostPoison.js");
  const r = await probeHostPoison({ url, canaryHost: typeof flags["canary-host"] === "string" ? flags["canary-host"] : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, poisoned: r.poisoned.length, detail: r.poisoned.slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "upload-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: upload-probe <url> <outdir> [--field file] [--bearer T]"); return 2; }
  const { probeUpload } = await import("../../domain/uploadProbe.js");
  const r = await probeUpload({ url, field: typeof flags.field === "string" ? flags.field : undefined, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, dangerous: r.dangerous.length, detail: r.dangerous.slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "graphql-batch": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: graphql-batch <endpoint> <outdir> [--query-template 'query { x {NEST} }'] [--max-depth N]"); return 2; }
  const { probeGraphqlBatch } = await import("../../domain/graphqlBatch.js");
  const r = await probeGraphqlBatch({ url, queryTemplate: typeof flags["query-template"] === "string" ? flags["query-template"] : undefined, maxDepth: num(flags["max-depth"]), outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, deepestDepth: Math.max(...r.depthLadder.filter(d => !d.rejected).map(d => d.depth), 0), maxAlias: Math.max(...r.aliasLadder.filter(a => !a.rejected).map(a => a.aliases), 0), unboundedDepth: r.unboundedDepth, unboundedAliases: r.unboundedAliases, depthLadder: r.depthLadder, artifacts: r.artifacts });
  return 0;
  },

  "entitlement-bypass": async (ctx) => {
    const { positional, flags, out, num, jobj, resolveProxy } = ctx;
  const [premium, account, dir] = positional;
  if (!premium || !account || !dir) { console.error("usage: entitlement-bypass <premiumUrl> <accountUrl> <outdir>"); return 2; }
  const { probeEntitlementBypass } = await import("../../domain/entitlementBypass.js");
  const r = await probeEntitlementBypass({ premiumUrl: premium, accountUrl: account, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ plan: r.plan, exploitable: r.exploitable, verdicts: r.verdicts, artifacts: r.artifacts });
  return r.exploitable ? 0 : 1;
  },
  "billing-tamper": async (ctx) => {
    const { positional, flags, out, num, jobj, resolveProxy } = ctx;
  const [url, dir] = positional;
  const amount = num(flags.amount);
  if (!url || !dir || amount === undefined) { console.error("usage: billing-tamper <checkoutUrl> <outdir> --body-template T --amount N [--currency USD] [--order-url U/{ID}]"); return 2; }
  const { probeBillingTamper } = await import("../../domain/billingTamper.js");
  const r = await probeBillingTamper({ url, bodyTemplate: String(flags["body-template"] ?? "{}"), outputRoot: dir, amount, currency: String(flags.currency ?? "USD"), plan: typeof flags.plan === "string" ? flags.plan : undefined, planCheap: typeof flags["plan-cheap"] === "string" ? flags["plan-cheap"] : undefined, coupon: typeof flags.coupon === "string" ? flags.coupon : undefined, orderUrl: typeof flags["order-url"] === "string" ? flags["order-url"] : undefined, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), contentType: typeof flags["content-type"] === "string" ? flags["content-type"] : undefined });
  out({ accepted: r.accepted, cases: r.cases, artifacts: r.artifacts });
  return r.accepted.length ? 0 : 1;
  },
};
