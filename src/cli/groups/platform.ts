import type { Ctx } from "../shared.js";

/** 平台 — 管道与证据 */
export const PlatformHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "auto": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [seed, dir] = positional;
  if (!seed || !dir) {
    console.error("usage: auto <seed> <outdir> [--chromium PATH] [--skip-runtime] [--proxy URL] [--cookie STR] [--timeout MS] [--max-pages N] [--rps N]");
    return 2;
  }
  const { runAutoPipeline } = await import("../../application/auto.js");
  out(
    await runAutoPipeline({
      seed,
      outputRoot: dir,
      chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
      proxy: await resolveProxy(flags),
      cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
      timeoutMs: num(flags.timeout),
      rps: num(flags.rps),
      skipRuntime: flags["skip-runtime"] === true,
      maxPages: num(flags["max-pages"]),
      resume: flags.fresh !== true,
    }),
  );
  return 0;
  },
  "auto-batch": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [seedsFile, dir] = positional;
  if (!seedsFile || !dir) {
    console.error("usage: auto-batch <seeds.txt> <outdir> [--chromium PATH] [--skip-runtime] [--notify URL]");
    return 2;
  }
  const { runBatch } = await import("../../application/batch.js");
  out(await runBatch({
    seedsFile, outputRoot: dir,
    chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined,
    proxy: await resolveProxy(flags),
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    skipRuntime: flags["skip-runtime"] === true,
    notifyWebhook: typeof flags.notify === "string" ? flags.notify : undefined,
  }));
  return 0;
  },
  "run-diff": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [oldRoot, newRoot] = positional;
  if (!oldRoot || !newRoot) {
    console.error("usage: run-diff <oldOutdir> <newOutdir>");
    return 2;
  }
  const { runDiff } = await import("../../application/runDiff.js");
  out(await runDiff({ oldRoot, newRoot }));
  return 0;
  },
  "gen-report": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [reportJson, dir] = positional;
  if (!reportJson || !dir) {
    console.error("usage: gen-report <report.json> <outdir>");
    return 2;
  }
  const { readFile } = await import("node:fs/promises");
  const { generateReport } = await import("../../application/report.js");
  const content = await readFile(reportJson, "utf8");
  out(await generateReport({ reportJson: content, outputRoot: dir }));
  return 0;
  },
  "save-evidence": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [inFile, dir] = positional;
  if (!inFile || !dir) {
    console.error("usage: save-evidence <items.json> <outdir>   (items: [{source,label?,content}])");
    return 2;
  }
  const { readFile } = await import("node:fs/promises");
  const { saveEvidence } = await import("../../application/evidence.js");
  const items = JSON.parse(await readFile(inFile, "utf8")) as {
    source: string; label?: string; content: string;
  }[];
  out(await saveEvidence({ outputRoot: dir, items }));
  return 0;
  },
  "evidence": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: evidence <outdir> put <file> [tag]|get <hash>|list"); return 2; }
  const { EvidenceStore } = await import("../../domain/graphs.js");
  const store = new EvidenceStore(dir);
  await store.load();
  if (action === "put") {
    const { readFile: rf } = await import("node:fs/promises");
    const blob = await store.put(await rf(positional[2] ?? ""), positional[3]);
    await store.save();
    out({ hash: blob.hash, bytes: blob.bytes });
    return 0;
  }
  if (action === "get") { const b = await store.get(positional[2] ?? ""); out({ found: b !== null, bytes: b?.length ?? 0 }); return 0; }
  if (action === "list") { out(store.entries()); return 0; }
  console.error("unknown action"); return 2;
  },
  "evidence-bind": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: evidence-bind <outdir> bind <findingId> <expectedV> <refsJson>|update|unbind|reorder|get <findingId>|export <findingId> <zipPath>"); return 2; }
  const mod = await import("../../domain/evidenceBinding.js");
  if (action === "get") { out(await mod.getBindings(dir, positional[2] ?? "")); return 0; }
  if (action === "export") { out(await mod.exportBindings({ root: dir, findingId: positional[2] ?? "", zipPath: positional[3] ?? "evidence.zip" })); return 0; }
  if (action === "bind") {
    const refs = JSON.parse(positional[4] ?? "[]");
    out(await mod.bindEvidence({ root: dir, findingId: positional[2] ?? "", expectedVersion: Number(positional[3] ?? 0), refs }));
    return 0;
  }
  if (action === "reorder") {
    const order = JSON.parse(positional[4] ?? "[]");
    out(await mod.reorderBindings({ root: dir, findingId: positional[2] ?? "", expectedVersion: Number(positional[3] ?? 0), order }));
    return 0;
  }
  if (action === "update" || action === "unbind") {
    const fn = action === "update" ? mod.updateBinding : mod.unbindEvidence;
    out(await fn({ root: dir, findingId: positional[2] ?? "", bindingId: positional[3] ?? "", expectedVersion: Number(positional[4] ?? 0) } as never));
    return 0;
  }
  console.error("unknown action"); return 2;
  },
  "exploration-graph": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: exploration-graph <outdir> overview|add_node <kind> <summary>|add_edge <from> <rel> <to>|anchor <node> <asset>|lineage <node>|set_state <node> <state>"); return 2; }
  const { ExplorationGraph } = await import("../../domain/graphs.js");
  const g = new ExplorationGraph(dir);
  await g.load();
  if (action === "overview") { out(g.overview()); return 0; }
  if (action === "add_node") { const n = g.addNode(positional[2] as never, positional[3] ?? ""); await g.save(); out({ id: n.id }); return 0; }
  if (action === "add_edge") { g.addEdge(positional[2] ?? "", positional[3] as never, positional[4] ?? ""); await g.save(); out({ ok: true }); return 0; }
  if (action === "anchor") { g.anchor(positional[2] ?? "", positional[3] ?? ""); await g.save(); out({ ok: true }); return 0; }
  if (action === "lineage") { out(g.lineage(positional[2] ?? "")); return 0; }
  if (action === "set_state") { g.setState(positional[2] ?? "", positional[3] as never); await g.save(); out({ ok: true }); return 0; }
  console.error("unknown action"); return 2;
  },
  "cold-graph": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: cold-graph <outdir> compact|expand <digestId> [--round N]"); return 2; }
  const { ExplorationGraph } = await import("../../domain/graphs.js");
  const cg = await import("../../domain/coldGraph.js");
  const g = new ExplorationGraph(dir);
  await g.load();
  const { stamps, round: prev } = await cg.loadStamps(dir);
  const round = num(flags.round) ?? prev + 1;
  if (action === "compact") {
    cg.touchLive(g, stamps, round - 1);
    const r = cg.compactGraph(g, stamps, round);
    await g.save(); await cg.saveStamps(dir, stamps, round);
    out({ digests: r.digests, folded: r.folded.length, rescued: r.rescued.length });
  } else {
    const r = cg.expandDigest(g, positional[2] ?? "", stamps, round);
    await g.save(); await cg.saveStamps(dir, stamps, round);
    out(r);
  }
  return 0;
  },
  "retest": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: retest <outdir> register <id> <json>|run <id>|list [--proxy P]"); return 2; }
  const mod = await import("../../domain/retest.js");
  if (action === "list") { out(await mod.listRetests(dir)); return 0; }
  if (action === "run") {
    out(await mod.runRetest({ root: dir, findingId: positional[2] ?? "", proxy: await resolveProxy(flags) }));
    return 0;
  }
  if (action === "register") {
    const spec = JSON.parse(positional[3] ?? "{}");
    out(await mod.registerFinding({ root: dir, id: positional[2] ?? "", name: spec.name ?? positional[2], severity: spec.severity ?? "medium", poc: spec.poc, predicates: spec.predicates }));
    return 0;
  }
  console.error("unknown action"); return 2;
  },
  "export-findings": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [file, dir, fmt] = positional;
  if (!file || !dir || !fmt || !["csv", "json", "md-all", "sarif"].includes(fmt)) { console.error("usage: export-findings <report.json> <outdir> csv|json|md-all|sarif"); return 2; }
  const { readFile } = await import("node:fs/promises");
  const { generateReportExports } = await import("../../application/report.js");
  const rep = JSON.parse(await readFile(file, "utf8")) as { findings?: unknown[] };
  const files = await generateReportExports({ outputRoot: dir, format: fmt as "csv" | "json" | "md-all" | "sarif", findings: (rep.findings ?? []) as never[] });
  out({ files });
  return 0;
  },
  "scan-platform": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [dir, action] = positional;
  if (!dir || !action) { console.error("usage: scan-platform <outdir> create-project|create-task|run-task|get-task|list-tasks|list-projects|list-assets|count-assets ..."); return 2; }
  const mod = await import("../../domain/scanPlatform.js");
  if (action === "create-project") {
    const [name, ...targets] = positional.slice(2);
    if (!name || targets.length === 0) { console.error("usage: scan-platform <dir> create-project <name> <target...>"); return 2; }
    out(await mod.createProject(dir, { name, targets }));
    return 0;
  }
  if (action === "create-task") {
    const [projectId, name, modulesCsv, targetsCsv] = positional.slice(2);
    if (!projectId || !name || !modulesCsv) { console.error("usage: scan-platform <dir> create-task <projectId> <name> <mod1,mod2> [target1,target2 | @sourceTaskId]"); return 2; }
    const modules = modulesCsv.split(",");
    const sourceTask = targetsCsv?.startsWith("@") ? targetsCsv.slice(1) : undefined;
    const targets = sourceTask ? undefined : targetsCsv?.split(",").filter(Boolean);
    out(await mod.createTask(dir, { projectId, name, modules, targets, sourceTask }));
    return 0;
  }
  if (action === "run-task") {
    const [taskId] = positional.slice(2);
    if (!taskId) { console.error("usage: scan-platform <dir> run-task <taskId> [--proxy p] [--cookie c]"); return 2; }
    out(await mod.runTask(dir, { taskId, proxy: typeof flags.proxy === "string" ? flags.proxy : undefined, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined }));
    return 0;
  }
  if (action === "get-task") { out(await mod.getTask(dir, positional[2] ?? "")); return 0; }
  if (action === "list-tasks") { out(await mod.listTasks(dir, positional[2])); return 0; }
  if (action === "list-projects") { out(await mod.listProjects(dir)); return 0; }
  if (action === "list-assets" || action === "count-assets") {
    const query: { type?: string; taskTag?: string; valuePrefix?: string; valueRegex?: string } = {};
    const [type, taskTag, valuePrefix, valueRegex] = positional.slice(2);
    if (type && type !== "-") query.type = type;
    if (taskTag && taskTag !== "-") query.taskTag = taskTag;
    if (valuePrefix && valuePrefix !== "-") query.valuePrefix = valuePrefix;
    if (valueRegex && valueRegex !== "-") query.valueRegex = valueRegex;
    if (action === "list-assets") { out(await mod.listAssets(dir, query, num(flags.page) ?? 1, num(flags.pageSize) ?? 50)); return 0; }
    out(await mod.countAssets(dir, query));
    return 0;
  }
  console.error("unknown action"); return 2;
  },
  "hunt-begin": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [goal, dir] = positional;
  if (!goal || !dir) {
    console.error("usage: hunt-begin <goal> <outdir> [--max-rounds N] [--max-cost N] [--max-duration-min N]");
    return 2;
  }
  const { huntBegin } = await import("../../application/huntDriver.js");
  out(await huntBegin({ goal, outputRoot: dir, maxRounds: num(flags["max-rounds"]), maxCost: num(flags["max-cost"]), maxDurationMin: num(flags["max-duration-min"]) }));
  return 0;
  },
  "hunt-record": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const rec = await jobj<Record<string, unknown>>(flags, "record");
  if (!dir || !rec) {
    console.error("usage: hunt-record <outdir> --record[-file] <record.json>  (fields: goals/intents/facts/findings/assets/goalsMet/round/costDelta/intentId/intentSummary)");
    return 2;
  }
  const { huntRecord } = await import("../../application/huntDriver.js");
  const r = await huntRecord({ outputRoot: dir, ...rec } as never);
  out({ accepted: r.accepted, dropped: r.dropped, dropReasons: r.dropReasons, goalsMet: r.graph.goals.filter((x) => x.met).length, goalsTotal: r.graph.goals.length, facts: r.graph.facts.length, findings: r.graph.findings.length, assets: r.graph.assets.length });
  return 0;
  },
  "hunt-overview": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  if (!dir) {
    console.error("usage: hunt-overview <outdir>");
    return 2;
  }
  const { huntOverview, exportLedgerEvidence } = await import("../../application/huntDriver.js");
  try { await exportLedgerEvidence(dir); } catch { /* best-effort */ }
  out(await huntOverview(dir));
  return 0;
  },
  "waf-adapt": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, payload, dir] = positional;
  if (!url || !payload || !dir) {
    console.error("usage: waf-adapt <url> <payload> <outdir> [--param NAME] [--in query|body|header|path] [--method M] [--max-attempts N]");
    return 2;
  }
  const { probeWafAdapt } = await import("../../domain/wafAdapt.js");
  const p = flags.param;
  const inWhere = flags.in;
  out(await probeWafAdapt({
    url, payload, outputRoot: dir,
    param: typeof p === "string" ? p : undefined,
    in: inWhere === "query" || inWhere === "body" || inWhere === "header" || inWhere === "path" ? inWhere : undefined,
    method: typeof flags.method === "string" ? flags.method : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxAttempts: num(flags["max-attempts"]),
  }));
  return 0;
  },
  "oob-confirm": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  const payloads = jarr(flags, "payloads");
  if (!url || !dir || !payloads) {
    console.error("usage: oob-confirm <url> <outdir> --payloads a,b [--positions-file JSON] [--method M] [--body STR] [--raw-body XML]");
    return 2;
  }
  const { probeOob } = await import("../../domain/oobConfirm.js");
  out(await probeOob({
    url, outputRoot: dir, payloads,
    positions: await jarrObj<{ param: string; in: "query" | "body" | "header" | "path" }>(flags, "positions"),
    method: typeof flags.method === "string" ? flags.method : undefined,
    body: typeof flags.body === "string" ? flags.body : undefined,
    rawBody: typeof flags["raw-body"] === "string" ? flags["raw-body"] : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    pollMs: num(flags.poll),
  }));
  return 0;
  },
  "smuggle-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [b, dir] = positional;
  if (!b || !dir) { console.error("usage: smuggle-probe <baseUrl> <outdir>"); return 2; }
  const { probeSmuggle } = await import("../../domain/smuggle.js");
  out(await probeSmuggle({ baseUrl: b, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "oidc-probe": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [b, dir] = positional;
  if (!b || !dir) { console.error("usage: oidc-probe <baseUrl> <outdir>"); return 2; }
  const { probeOidc } = await import("../../domain/oidc.js");
  out(await probeOidc({ baseUrl: b, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "cors": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [base, dir] = positional;
  if (!base || !dir) {
    console.error("usage: cors <baseUrl> <outdir>");
    return 2;
  }
  const { probeCors } = await import("../../domain/cors.js");
  out(await probeCors({ baseUrl: base, outputRoot: dir, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "cors-deep": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: cors-deep <url> <outdir> [--subdomains a,b]"); return 2; }
  const { probeCorsDeep } = await import("../../domain/corsDeep.js");
  const strListC = (v: string | boolean | undefined): string[] | undefined => typeof v === "string" && v.length > 0 ? v.split(",").map(x => x.trim()).filter(Boolean) : undefined;
  const r = await probeCorsDeep({ url, subdomains: strListC(flags.subdomains), outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, exploitable: r.exploitable.length, detail: r.exploitable, preflightMethods: r.preflightMethods, artifacts: r.artifacts });
  return 0;
  },
  "ws-auth": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: ws-auth <wsUrl> <outdir> [--origins a,b]"); return 2; }
  const { probeWsAuth } = await import("../../domain/wsAuth.js");
  const strListW = (v: string | boolean | undefined): string[] | undefined => typeof v === "string" && v.length > 0 ? v.split(",").map(x => x.trim()).filter(Boolean) : undefined;
  const r = await probeWsAuth({ url, origins: strListW(flags.origins), outputRoot: dir, headers: await jobj<Record<string, string>>(flags, "headers"), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, anonymousAccepted: r.anonymousAccepted, crossOriginAccepted: r.crossOriginAccepted, pushWithoutAuth: r.pushWithoutAuth, cases: r.cases, artifacts: r.artifacts });
  return 0;
  },
  "graphql-deep": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [ep, dir] = positional;
  if (!ep || !dir) { console.error("usage: graphql-deep <endpoint> <outdir> [--prev FILE]"); return 2; }
  const { probeGraphqlDeep } = await import("../../domain/graphqlDeep.js");
  out(await probeGraphqlDeep({ endpoint: ep, outputRoot: dir, previousSchemaFile: typeof flags.prev === "string" ? flags.prev : undefined, proxy: await resolveProxy(flags) }));
  return 0;
  },
  "mine-params": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  const mergedFile = typeof flags.merged === "string" ? flags.merged : undefined;
  const url = typeof flags.url === "string" ? flags.url : undefined;
  if (!dir || (!mergedFile && !url)) {
    console.error("usage: mine-params <outdir> (--merged params_merged.json | --url URL [--in query|cookie|header] [--learn] [--max-words N] [--bucket N] | --remove-diff --merged F --base URL) [--max-endpoints N]");
    return 2;
  }
  if (flags["remove-diff"] === true) {
    if (!mergedFile) { console.error("--remove-diff requires --merged"); return 2; }
    const { probeParams } = await import("../../application/paramProbe.js");
    out(await probeParams({ mergedFile, outputRoot: dir, baseUrl: typeof flags.base === "string" ? flags.base : undefined, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), maxEndpoints: num(flags["max-endpoints"]) }));
    return 0;
  }
  if (!url) { console.error("--url required for name-guess"); return 2; }
  const { mineHiddenParams } = await import("../../domain/hiddenParams.js");
  const inWhere = flags.in;
  out(await mineHiddenParams({
    url, outputRoot: dir,
    in: inWhere === "query" || inWhere === "cookie" || inWhere === "header" ? inWhere : undefined,
    words: jarr(flags, "words"),
    learn: flags.learn === true,
    method: typeof flags.method === "string" ? flags.method : undefined,
    body: typeof flags.body === "string" ? flags.body : undefined,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxWords: num(flags["max-words"]),
    bucketSize: num(flags.bucket),
  }));
  return 0;
  },
  "probe-params": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [mergedFile, dir] = positional;
  if (!mergedFile || !dir) {
    console.error("usage: probe-params <params_merged.json> <outdir> [--max N] [--cookie STR]");
    return 2;
  }
  const { probeParams } = await import("../../application/paramProbe.js");
  out(
    await probeParams({
      mergedFile,
      outputRoot: dir,
      cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
      proxy: await resolveProxy(flags),
      timeoutMs: num(flags.timeout),
      maxEndpoints: num(flags.max),
    }),
  );
  return 0;
  },
  "pii-scan": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [recordRoot, dir] = positional;
  if (!recordRoot || !dir) {
    console.error("usage: pii-scan <recordRoot> <outdir> [--skip-binary] [--max-blobs N]");
    return 2;
  }
  const { scanTrafficPii } = await import("../../domain/piiScan.js");
  const r = await scanTrafficPii({
    recordRoot, outputRoot: dir,
    skipBinary: flags["skip-binary"] === true,
    maxBlobs: num(flags["max-blobs"]),
  });
  out({ blobsScanned: r.blobsScanned, exposures: r.exposures.map((e) => ({ method: e.method, url: e.url, kinds: e.kinds })), credentialPairs: r.credentialPairs.map((c) => ({ name: c.name, url: c.url, method: c.method })), artifacts: r.artifacts });
  return 0;
  },
  "replay-tamper": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [recordRoot, dir] = positional;
  const rules = await jarrObj<{ field: string; in: "body" | "query"; value: string | number | boolean | null; label?: string }>(flags, "rules");
  if (!recordRoot || !dir) {
    console.error("usage: replay-tamper <recordRoot> <outdir> [--ids a,b] [--rules-file JSON] [--apply] [--max N]");
    return 2;
  }
  const { replayTamper } = await import("../../domain/replayTamper.js");
  out(await replayTamper({
    recordRoot, outputRoot: dir,
    exchangeIds: jarr(flags, "ids"),
    rules: (rules ?? []).map((x) => ({ ...x, label: x.label ?? `${x.field}=${String(x.value)}` })),
    cookie: typeof flags.cookie === "string" ? flags.cookie : undefined,
    extraHeaders: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    maxExchanges: num(flags.max),
    applyTamper: flags.apply === true,
  }));
  return 0;
  },
};
