import type { Ctx } from "../shared.js";
import { resolveHost } from "../../application/dns.js";
import { httpProbe } from "../../application/probe.js";

/** 侦察 — 资产与面测绘 */
export const ReconHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "subdomains": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [domain, dir] = positional;
  if (!domain || !dir) {
    console.error("usage: subdomains <domain> <outdir> [--wordlist FILE]");
    return 2;
  }
  const { discoverSubdomains } = await import("../../domain/subdomains.js");
  let wl: string[] | undefined;
  if (typeof flags.wordlist === "string" && flags.wordlist.trim() !== "") {
    try {
      const t = await (await import("node:fs/promises")).readFile(flags.wordlist, "utf8");
      wl = t.split("\n").map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));
    } catch (err) {
      // A requested-but-unreadable wordlist must be loud, not a silent
      // empty brute pass the user believes ran.
      console.error(`wordlist unreadable (${(err as Error).message}) — falling back to built-in prefixes`);
    }
  }
  out(await discoverSubdomains({ domain, outputRoot: dir, proxy: await resolveProxy(flags), wordlist: await wl }));
  return 0;
  },
  "subdomain-alter": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [domain, dir] = positional;
  const hosts = jarr(flags, "hosts");
  if (!domain || !dir || !hosts) {
    console.error("usage: subdomain-alter <domain> <outdir> --hosts a,b [--resolve] [--max-candidates N] [--nameservers a,b] [--concurrency N]");
    return 2;
  }
  const { alterSubdomains } = await import("../../domain/subdomainAlter.js");
  const r = await alterSubdomains({
    hosts, domain,
    resolve: flags.resolve === true,
    maxCandidates: num(flags["max-candidates"]),
    nameservers: jarr(flags, "nameservers"),
    concurrency: num(flags.concurrency),
  });
  const { writeFile: wf, mkdir: mk } = await import("node:fs/promises");
  await mk(dir, { recursive: true });
  const { join } = await import("node:path");
  const bodyStr = JSON.stringify({ generated: r.generated, resolved: r.resolved, samples: r.samples }, null, 2);
  const path = join(dir, "subdomain_alterations.json");
  await wf(path, bodyStr, "utf8");
  out({ generated: r.generated, resolved: r.resolved, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] });
  return 0;
  },
  "port-scan": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [host, dir] = positional;
  if (!host || !dir) {
    console.error("usage: port-scan <host|ip> <outdir> [--ports 80,443 [--timeout MS] [--concurrency N]");
    return 2;
  }
  const ports = typeof flags.ports === "string" ? flags.ports.split(",").map((x) => Number(x.trim())).filter((n) => n > 0) : undefined;
  const { scanPorts } = await import("../../domain/portScan.js");
  out(await scanPorts({ host, outputRoot: dir, ports, timeoutMs: num(flags.timeout), concurrency: num(flags.concurrency) }));
  return 0;
  },
  "dns-resolve": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  if (positional.length === 0) {
    console.error("usage: dns-resolve <host> [...]");
    return 2;
  }
  const results = [];
  for (const host of positional) results.push(await resolveHost(host));
  out({ results });
  return 0;
  },
  "http-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const url = positional[0];
  if (!url) {
    console.error("usage: http-probe <url>");
    return 2;
  }
  out(
    await httpProbe({
      url,
      cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
      proxy: await resolveProxy(flags),
      timeoutMs: num(flags.timeout),
    }),
  );
  return 0;
  },
  "enrich": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const seeds = positional.filter((p) => !p.startsWith("-"));
  const dir = typeof flags.out === "string" ? flags.out : undefined;
  if (seeds.length === 0 || !dir) {
    console.error("usage: enrich <seed...> --out DIR [--no-http] [--proxy URL] [--cookie STR] [--timeout MS]");
    return 2;
  }
  const { enrichAssets } = await import("../../application/enrich.js");
  out(
    await enrichAssets({
      seeds,
      outputRoot: dir,
      proxy: await resolveProxy(flags),
      cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
      timeoutMs: num(flags.timeout),
      http: flags["no-http"] !== true,
    }),
  );
  return 0;
  },
  "wayback": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [target, dir] = positional;
  if (!target || !dir) {
    console.error("usage: wayback <domain> <outdir> [--max N]");
    return 2;
  }
  const { fetchWayback } = await import("../../domain/sourcemap.js");
  out(await fetchWayback({ target, outputRoot: dir, maxUrls: num(flags.max), proxy: await resolveProxy(flags) }));
  return 0;
  },
  "fingerprint": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [base, dir] = positional;
  if (!base || !dir) {
    console.error("usage: fingerprint <baseUrl> <outdir>");
    return 2;
  }
  const { fingerprint } = await import("../../domain/fingerprint.js");
  out(await fingerprint({ baseUrl: base, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "paths": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [base, dir] = positional;
  if (!base || !dir) {
    console.error("usage: paths <baseUrl> <outdir> [--cookie STR]");
    return 2;
  }
  const { probePaths } = await import("../../domain/pathProbe.js");
  out(await probePaths({ baseUrl: base, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "dir-fuzz": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const preset = flags.preset;
  const base = typeof flags.base === "string" ? flags.base : undefined;
  const url = typeof flags.url === "string" ? flags.url : undefined;
  if (preset === "sensitive" || preset === "backups") {
    if (!dir || !base) {
      console.error(`usage: dir-fuzz <outdir> --preset ${preset} --base URL [--cookie STR]`);
      return 2;
    }
    if (preset === "sensitive") {
      const { probePaths } = await import("../../domain/pathProbe.js");
      out(await probePaths({ baseUrl: base, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) }));
    } else {
      const { findBackups } = await import("../../domain/backupFind.js");
      out(await findBackups({ baseUrl: base, outputRoot: dir, targets: jarr(flags, "targets"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), maxCandidates: num(flags.max) }));
    }
    return 0;
  }
  if (!dir || !url) {
    console.error("usage: dir-fuzz <outdir> --url URL [--wordlist-file F] [--extensions html,php] [--recursion] [--calibration N] [--match-status 200,301] [--filter-size N] [--delay-ms N]");
    return 2;
  }
  const { dirFuzz } = await import("../../domain/dirFuzz.js");
  out(await dirFuzz({
    url, outputRoot: dir,
    wordlistFile: typeof flags["wordlist-file"] === "string" ? flags["wordlist-file"] : undefined,
    words: jarr(flags, "words"),
    extensions: jarr(flags, "extensions"),
    recursion: flags.recursion === true,
    recursionDepth: num(flags["recursion-depth"]),
    calibration: num(flags.calibration),
    matchStatus: (typeof flags["match-status"] === "string" ? flags["match-status"].split(",").map((x) => Number(x.trim())).filter((n) => n > 0) : undefined),
    filterSize: (typeof flags["filter-size"] === "string" ? flags["filter-size"].split(",").map((x) => Number(x.trim())).filter((n) => n >= 0) : undefined),
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxWords: num(flags.max),
    delayMs: num(flags["delay-ms"]),
  }));
  return 0;
  },
  "nuclei-lite": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [b, dir] = positional;
  if (!b || !dir) { console.error("usage: nuclei-lite <baseUrl> <outdir>"); return 2; }
  const { runNucleiLite } = await import("../../domain/nucleiLite.js");
  out(await runNucleiLite({ baseUrl: b, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "admin-surface": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [baseUrl, dir] = positional;
  if (!baseUrl || !dir) {
    console.error("usage: admin-surface <baseUrl> <outdir>");
    return 2;
  }
  const { probeAdminSurface } = await import("../../domain/adminSurface.js");
  out(await probeAdminSurface({
    baseUrl, outputRoot: dir,
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
  }));
  return 0;
  },
  "info-leak": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: info-leak <baseUrl> <outdir>"); return 2; }
  const { probeInfoLeak } = await import("../../domain/infoLeak.js");
  const r = await probeInfoLeak({ baseUrl: url, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, findings: r.findings.length, bySeverity: { high: r.findings.filter(f => f.severity === "high").length, medium: r.findings.filter(f => f.severity === "medium").length, low: r.findings.filter(f => f.severity === "low").length }, detail: r.findings.slice(0, 15), artifacts: r.artifacts });
  return 0;
  },
  "coverage": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [b, dir] = positional;
  if (!b || !dir) { console.error("usage: coverage <baseUrl> <outdir> [--cookie C] [--chromium P] [--max N]"); return 2; }
  const { runCoverage } = await import("../../domain/coverage.js");
  out(await runCoverage({ baseUrl: b, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined, maxClicksPerCategory: num(flags.max), proxy: await resolveProxy(flags) }));
  return 0;
  },
  "site-map": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [b, dir] = positional;
  if (!b || !dir) { console.error("usage: site-map <baseUrl> <outdir> [--mode m] [--app t]"); return 2; }
  const { buildSiteMap } = await import("../../domain/siteMap.js");
  out(await buildSiteMap({ baseUrl: b, outputRoot: dir, runtimeMode: (flags.mode === "depth" || flags.mode === "coverage" || flags.mode === "both" ? flags.mode : "static-only"), appType: typeof flags.app === "string" ? flags.app : undefined }));
  return 0;
  },
  "asset-graph": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: asset-graph <outdir> counts|query <type>|upsert <type> <value>|upsert_url <url>"); return 2; }
  const { AssetStore } = await import("../../domain/graphs.js");
  const st = new AssetStore(dir);
  await st.load();
  if (action === "counts") { out(st.countsByType()); return 0; }
  if (action === "query") { out(st.queryByType((positional[2] ?? "subdomain") as never).slice(0, 300)); return 0; }
  if (action === "upsert") { st.upsert({ type: positional[2] as never, value: positional[3] ?? "" }); await st.save(); out({ ok: true }); return 0; }
  if (action === "upsert_url") { st.upsertUrl(positional[2] ?? ""); await st.save(); out({ ok: true }); return 0; }
  console.error("unknown action"); return 2;
  },
};
