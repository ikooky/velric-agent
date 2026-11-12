import type { Ctx } from "../shared.js";
import { harvestStatic } from "../../application/harvest.js";
import { spiderMpa } from "../../application/spider.js";

/** 内容 — 抓取与语料 */
export const ContentHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "harvest": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [base, dir] = positional;
  if (!base || !dir) {
    console.error("usage: harvest <url> <outdir>");
    return 2;
  }
  out(
    await harvestStatic({
      baseUrl: base,
      outputRoot: dir,
      proxy: await resolveProxy(flags),
      cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
      timeoutMs: num(flags.timeout),
    }),
  );
  return 0;
  },
  "spider": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [base, dir] = positional;
  if (!base || !dir) {
    console.error("usage: spider <url> <outdir>");
    return 2;
  }
  out(
    await spiderMpa({
      baseUrl: base,
      outputRoot: dir,
      cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
      proxy: await resolveProxy(flags),
      maxPages: num(flags.max),
      depth: num(flags.depth),
      exclude: typeof flags.exclude === "string" ? flags.exclude : undefined,
    }),
  );
  return 0;
  },
  "extract-routes": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [jsDir, dir] = positional;
  if (!jsDir || !dir) {
    console.error("usage: extract-routes <jsdir> <outdir>");
    return 2;
  }
  const { readJsCorpus } = await import("../../application/harvest.js");
  const { writeArtifact } = await import("../../adapters/artifacts.js");
  const { classifyPaths, extractPathLiterals, extractRoutes } = await import(
    "../../domain/endpoints.js"
  );
  const corpus = await readJsCorpus(jsDir);
  if (corpus.length === 0) {
    console.error(`no .js files under ${jsDir}`);
    return 1;
  }
  const api = new Set<string>();
  const other = new Set<string>();
  const routes = new Set<string>();
  for (const f of corpus) {
    const c = classifyPaths(extractPathLiterals(f.text));
    for (const p of c.api) api.add(p);
    for (const p of c.other) other.add(p);
    for (const r of extractRoutes(f.text)) routes.add(r);
  }
  await writeArtifact(dir, "api_static.txt", [...api].sort().join("\n"));
  await writeArtifact(dir, "paths_other.txt", [...other].sort().join("\n"));
  await writeArtifact(dir, "routes.txt", [...routes].sort().join("\n"));
  out({ files: corpus.length, api: api.size, other: other.size, routes: routes.size });
  return 0;
  },
  "sourcemaps": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, outDir] = positional;
  if (!dir || !outDir) {
    console.error("usage: sourcemaps <jsDir> <outdir> [--base URL]");
    return 2;
  }
  const { detectSourceMaps } = await import("../../domain/sourcemap.js");
  out(await detectSourceMaps({ outputRoot: outDir, jsDir: dir, baseUrl: typeof flags.base === "string" ? flags.base : undefined, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "deobfuscate": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [jsDir, dir] = positional;
  if (!jsDir || !dir) {
    console.error("usage: deobfuscate <jsDir> <outdir> [--action deobf|analyze] [--max-files N] [--max-file-bytes N]");
    return 2;
  }
  const action = flags.action;
  if (action === "analyze") {
    const { analyzeCorpus } = await import("../../domain/jsAnalyze.js");
    out(await analyzeCorpus({ jsDir, outputRoot: dir, maxFiles: num(flags["max-files"]), maxFileBytes: num(flags["max-file-bytes"]) }));
  } else {
    const { deobfuscateCorpus } = await import("../../domain/deobf.js");
    out(await deobfuscateCorpus({ jsDir, outputRoot: dir, maxFiles: num(flags["max-files"]), maxFileBytes: num(flags["max-file-bytes"]) }));
  }
  return 0;
  },
  "git-restore": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [base, dir] = positional;
  if (!base || !dir) {
    console.error("usage: git-restore <baseUrl> <outdir>");
    return 2;
  }
  const { restoreGit } = await import("../../domain/gitRestore.js");
  out(await restoreGit({ baseUrl: base, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "backup-unpack": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [urlFile, dir] = positional;
  if (!urlFile || !dir) { console.error("usage: backup-unpack <urls.txt> <outdir>"); return 2; }
  const { readFile: rf } = await import("node:fs/promises");
  const urls = (await rf(urlFile, "utf8")).split("\n").map((l) => l.trim()).filter(Boolean);
  const { unpackBackups } = await import("../../domain/backupUnpack.js");
  out(await unpackBackups({ urls, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "sqlite-read": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [f, dir] = positional;
  if (!f || !dir) { console.error("usage: sqlite-read <file.db> <outdir>"); return 2; }
  const { readSqlite } = await import("../../domain/sqliteRead.js");
  out(await readSqlite({ file: f, outputRoot: dir }));
  return 0;
  },
  "archive-recover": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [u, dir] = positional;
  if (!u || !dir) { console.error("usage: archive-recover <url> <outdir>"); return 2; }
  const { recoverUrl } = await import("../../domain/archive.js");
  out(await recoverUrl({ url: u, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "url-refine": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const urls = jarr(flags, "urls") ?? (typeof flags["urls-file"] === "string" ? (await (await import("node:fs/promises")).readFile(flags["urls-file"], "utf8")).split("\n").map((l) => l.trim()).filter(Boolean) : undefined);
  if (!dir || !urls || urls.length === 0) {
    console.error("usage: url-refine <outdir> --urls a,b (or --urls-file FILE) [--action dedupe|classify] [--keep-static] [--fuzzy] [--params has|none]");
    return 2;
  }
  const { dedupeUrls, classifyUrls } = await import("../../domain/urlRefine.js");
  const { writeFile: wf, mkdir: mk } = await import("node:fs/promises");
  await mk(dir, { recursive: true });
  const { join } = await import("node:path");
  if (flags.action === "classify") {
    const r = classifyUrls(urls);
    const bodyStr = JSON.stringify(r, null, 2);
    const path = join(dir, "classified_urls.json");
    await wf(path, bodyStr, "utf8");
    out({ ...r, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] });
  } else {
    const r = dedupeUrls({ urls, keepStatic: flags["keep-static"] === true, keepContent: flags["keep-content"] === true, fuzzy: flags.fuzzy === true, whitelist: jarr(flags, "whitelist"), params: flags.params === "has" || flags.params === "none" ? flags.params : undefined });
    const bodyStr = JSON.stringify(r, null, 2);
    const path = join(dir, "deduped_urls.json");
    await wf(path, bodyStr, "utf8");
    out({ ...r, artifacts: [{ path, bytes: Buffer.byteLength(bodyStr) }] });
  }
  return 0;
  },
  "screenshot": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const urls = jarr(flags, "urls");
  if (!dir || !urls) {
    console.error("usage: screenshot <outdir> --urls a,b [--chromium PATH] [--concurrency N] [--cluster] [--timeout MS]");
    return 2;
  }
  const { captureScreenshots } = await import("../../domain/screenshot.js");
  out(await captureScreenshots({
    urls, outputRoot: dir,
    chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
    concurrency: num(flags.concurrency),
    timeoutMs: num(flags.timeout),
    cluster: flags.cluster === true,
    proxy: await resolveProxy(flags),
  }));
  return 0;
  },
  "traffic-recorder": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir] = positional;
  if (!dir) { console.error("usage: traffic-recorder <outdir> [--port N] [--upstream P] [--max N] [--daemon] [--seconds S]"); return 2; }
  const { TrafficRecorder } = await import("../../domain/trafficRecorder.js");
  const rec = new TrafficRecorder({ outputRoot: dir, port: num(flags.port), upstreamProxy: typeof flags.upstream === "string" ? flags.upstream : undefined, maxExchanges: num(flags.max), mitm: flags.mitm === true });
  const port = await rec.start(num(flags.port) || 0);
  console.error(`recorder listening on 127.0.0.1:${port}`);
  // Ctrl-C must flush and release the port so rec.stop() stays
  // reachable.
  const stopped = new Promise<void>((resolve) => {
    const stop = (): void => { void rec.stop().finally(resolve); };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  if (flags.daemon) {
    const secs = num(flags.seconds) || 3600;
    await new Promise((r) => setTimeout(r, secs * 1000));
    await rec.stop();
  } else {
    console.error("press Ctrl-C to stop; exchanges: " + rec.getExchanges().length);
    await stopped;
  }
  return 0;
  },
  "traffic-query": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: traffic-query <outdir> search [--host H --status N --method M --text T --page N]|get <id>"); return 2; }
  const mod = await import("../../domain/trafficRecorder.js");
  if (action === "get") { out(await mod.getTraffic({ outputRoot: dir, id: positional[2] ?? "" })); return 0; }
  out(await mod.searchTraffic({ outputRoot: dir, host: typeof flags.host === "string" ? flags.host : undefined, status: num(flags.status), method: typeof flags.method === "string" ? flags.method : undefined, text: typeof flags.text === "string" ? flags.text : undefined, page: num(flags.page), pageSize: num(flags.pageSize) }));
  return 0;
  },

  "envelope-break": async (ctx) => {
    const { positional, flags, out, jarr } = ctx;
  const [responseArg, dir] = positional;
  if (!responseArg || !dir) { console.error("usage: envelope-break <envelope.json|inline> <outdir> --keys k1,k2 [--keys-file F]"); return 2; }
  const keys = jarr(flags, "keys") ?? [];
  const { crackEnvelope } = await import("../../domain/envelopeBreak.js");
  const r = await crackEnvelope({ response: responseArg, outputRoot: dir, keys });
  out({ cracked: r.cracked, keyUsed: r.keyUsed, scheme: r.scheme, plaintextPrefix: r.plaintextPrefix, parsed: r.parsed, tried: r.tried, artifacts: r.artifacts });
  return r.cracked ? 0 : 1;
  },
};
