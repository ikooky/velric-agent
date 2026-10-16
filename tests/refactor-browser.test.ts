import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium, type Browser } from "playwright-core";
import { DEFAULT_HOOK_CONFIG, buildPreloadScript } from "../src/domain/preload.js";

const scratch = process.env.TMPDIR ?? "/root/.hermes/cache/scratch";
const root = () => mkdtemp(join(scratch, "browser-refactor-"));
let server: Server, browser: Browser, base = "";
const wire: { path: string; cookie: string; auth: string; body: string; method: string; headers: import("node:http").IncomingHttpHeaders }[] = [];
let loginCount = 0;
beforeAll(async () => {
  server = createServer(async (q, s) => {
    let body = ""; for await (const c of q) body += c;
    const path = new URL(q.url!, "http://fixture").pathname;
    wire.push({ path, cookie: q.headers.cookie ?? "", auth: q.headers.authorization ?? "", body, method: q.method ?? "", headers: q.headers });
    if (path === "/login-session") { loginCount++; s.writeHead(200, { "content-type": "application/json", "set-cookie": ["csrf=guest; Path=/", `sid=s${loginCount}; Path=/; HttpOnly`, "outside=bad; Domain=example.invalid; Path=/"] }); s.end(JSON.stringify({ access_token: `t${loginCount}` })); return; }
    if (path === "/guest-login") { s.writeHead(200, { "content-type": "application/json", "set-cookie": "csrf=guest; Path=/" }); s.end('{"ok":false}'); return; }
    if (path === "/rotate") { s.writeHead(200, { "content-type": "application/json", "set-cookie": "sid=rotated; Path=/; HttpOnly" }); s.end('{"access_token":"rotated-token","ok":true}'); return; }
    if (path === "/need-rotation") { const ok = q.headers.cookie?.includes("sid=rotated") && q.headers.authorization === "Bearer rotated-token"; s.writeHead(ok ? 200 : 401, { "content-type": "text/plain" }); s.end(ok ? 'AUTHENTICATED' : 'expired'); return; }
    if (path === "/retry-wall") { s.writeHead(200, { "content-type": "text/html" }); s.end('<html>please sign in<input type="password"></html>'); return; }
    if (path === "/scope") { s.writeHead(200, { "content-type": "text/html" }); s.end(`<a href="http://127.0.0.1.evil.invalid:${new URL(base).port}/leak">bad</a><script src="http://localhost:${new URL(base).port}/external.js"></script><script src="/local.js"></script>`); return; }
    if (path.endsWith('.js')) { s.writeHead(200, { "content-type": "application/javascript" }); s.end('fetch("/api/fresh")'); return; }
    if (path === "/coverage-a" || path === "/coverage-b") { s.writeHead(200, { "content-type": "text/html" }); s.end(`<!doctype html><title>coverage</title><nav><a href="/coverage-b">Next</a></nav><input type="search" onkeydown="if(event.key==='Enter')fetch('/query',{method:'POST',body:JSON.stringify({q:this.value})})"><script>fetch('/query',{method:'POST',body:'{"q":"initial"}'})</script>`); return; }
    if (path === "/query") { s.writeHead(200, { "content-type": "application/json" }); s.end('{"ok":true}'); return; }
    if (path === "/screenshot-set") { s.writeHead(200, { "content-type": "text/html", "set-cookie": "leak=present; Path=/" }); s.end('<title>set</title><script>localStorage.setItem("leak","present")</script>'); return; }
    if (path === "/screenshot-check") { s.writeHead(200, { "content-type": "text/html" }); s.end('<script>document.title=localStorage.getItem("leak")||"clean"</script>'); return; }
    if (path === '/login-browser') { s.writeHead(200,{'content-type':'text/html','set-cookie':'sid=guest; Path=/; HttpOnly'}); s.end('<form method="POST" action="/browser-submit"><input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form>'); return; }
    if (path === '/browser-submit') { const ok=body.includes('username=valid'); s.writeHead(302,{location:ok?'/member':'/login-error','set-cookie':ok?'sid=member; Path=/; HttpOnly':'tracking=new; Path=/'}); s.end(); return; }
    if (path === '/member' || path === '/login-error') { s.writeHead(200,{'content-type':'text/html'}); s.end(path==='/member'?'AUTHENTICATED_MEMBER':'Invalid credentials'); return; }
    if (path === "/events") { s.writeHead(200, { "content-type": "text/event-stream" }); s.end("data: fixture-message\n\n"); return; }
    if (path === "/api") { s.writeHead(200, { "content-type": "application/json" }); s.end(JSON.stringify({ code: 401, message: "unauthorized", data: null })); return; }
    if (path === "/stream") { s.writeHead(200, { "content-type": "text/plain" }); s.write("prefix"); setTimeout(() => s.end("suffix"), 600); return; }
    s.writeHead(200, { "content-type": "text/html" }); s.end("<!doctype html><title>fixture</title>");
  });
  await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as {port:number}).port}`;
  browser = await chromium.launch({ executablePath: "/usr/bin/chromium", headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
});
afterAll(async () => { await browser?.close(); server?.closeAllConnections(); await new Promise<void>(r => server?.close(() => r())); });

describe("browser reliability", () => {
  it("records URL/init overrides without delaying streams and gates only explicitly", async () => {
    const ctx = await browser.newContext();
    try {
      await ctx.addInitScript(buildPreloadScript(DEFAULT_HOOK_CONFIG));
      const page = await ctx.newPage(); await page.goto(base);
      const r = await page.evaluate(`(async () => {
        await fetch(new URL('/api',location.href),{method:'PUT',headers:new Headers([['x-url','yes']]),body:'url-body'});
        await fetch(new Request(location.origin+'/api',{method:'POST',body:'original',headers:{'x-old':'old'}}),{method:'PATCH',body:'override',headers:[['x-new','yes']]});
        const start=performance.now(); const streamed=await fetch('/stream'); const elapsed=performance.now()-start; const text=await streamed.text();
        history.pushState({},'', '/login');
        return {elapsed,text,path:location.pathname,details:window.__API_RECON_DETAIL__};
      })()` ) as any;
      expect(r.elapsed).toBeLessThan(400); expect(r.text).toBe('prefixsuffix'); expect(r.path).toBe('/login');
      expect(r.details.find((d:any) => d.method === 'PUT')).toMatchObject({ url: base+'/api', reqBody: 'url-body', reqHeaders:{'x-url':'yes'} });
      expect(r.details.find((d:any) => d.method === 'PATCH')).toMatchObject({ reqBody: 'override', reqHeaders:{'x-new':'yes'} });
      const multipart = await page.evaluate(`(async()=>{const body=new FormData();body.append('business','kept');await fetch('/api',{method:'POST',body});const request=new Request(location.origin+'/api',{method:'POST',body:'used'});await fetch(request);await new Promise(r=>setTimeout(r,40));return {used:request.bodyUsed,detail:window.__API_RECON_DETAIL__.find(d=>d.reqBody&&d.reqBody.includes('name="business"'))}})()` ) as any;
      const sent=wire.findLast(w=>w.body.includes('name="business"'))!;
      expect(multipart.detail.reqBody).toBe(sent.body); expect(multipart.detail.reqHeaders['content-type']).toBe(sent.headers['content-type']); expect(multipart.used).toBe(true);
      const gated = await browser.newContext();
      try {
        await gated.addInitScript(buildPreloadScript({...DEFAULT_HOOK_CONFIG,mode:'gate-defeat'})); const p = await gated.newPage(); await p.goto(base);
        const g = await p.evaluate(`(async()=>{const j=await (await fetch('/api')).json();history.pushState({},'', '/login');return {j,path:location.pathname,detail:window.__API_RECON_DETAIL__[0]}})()` ) as any;
        expect(g.j.code).toBe(0); expect(g.path).toBe('/'); expect(JSON.parse(g.detail.responseBody).code).toBe(401); expect(g.detail.modified).toBe(true);
      } finally { await gated.close(); }
    } finally { await ctx.close(); }
  }, 15000);
  it("rotates cookies and bearer on every response and rechecks a retried login wall", async () => {
    const { crawlSession } = await import('../src/domain/sessionCrawl.js');
    const outputRoot = await root();
    const result = await crawlSession({baseUrl:base,loginUrl:base+'/login-session',username:'test',password:'test',outputRoot,endpoints:['/rotate','/need-rotation','/retry-wall',`http://localhost:${new URL(base).port}/external`],maxRelogins:1});
    expect(result.pages.find(p=>p.url.endsWith('/need-rotation'))?.status).toBe(200);
    expect(result.pages.find(p=>p.url.endsWith('/retry-wall'))?.authState).not.toBe('authenticated');
    expect(result.blocked).toContain(base+'/retry-wall');
    expect(result.blocked).toContain(`http://localhost:${new URL(base).port}/external`);
    const received = wire.filter(w=>w.path==='/need-rotation').at(-1)!;
    expect(received.cookie).toContain('sid=rotated'); expect(received.cookie).not.toContain('outside='); expect(received.auth).toBe('Bearer rotated-token');
  },15000);
  it("does not accept a visitor CSRF cookie as authenticated login", async()=>{
    const {crawlSession}=await import('../src/domain/sessionCrawl.js');
    await expect(crawlSession({baseUrl:base,loginUrl:base+'/guest-login',username:'test',password:'test',outputRoot:await root(),endpoints:['/retry-wall']})).rejects.toThrow(/login|auth/i);
  });
  it("never sends target cookies to external scripts and excludes old corpus on a zero-result rerun", async()=>{
    const {harvestStatic,readJsCorpus}=await import('../src/application/harvest.js');
    const {spiderMpa}=await import('../src/application/spider.js');
    const outputRoot=await root();
    const h=await harvestStatic({baseUrl:base+'/scope',outputRoot,cookie:'secret=target',maxRounds:0});
    expect(h.jsDownloaded).toBe(2);
    expect(wire.filter(w=>w.path==='/external.js').at(-1)?.cookie).toBe('');
    expect((await readJsCorpus(join(outputRoot,'js'))).length).toBe(2);
    const spider=await spiderMpa({baseUrl:base+'/scope',outputRoot:await root(),cookie:'secret=target',delayMs:0,depth:1});
    expect(spider.crawled).toBe(1);
    expect(wire.filter(w=>w.path==='/external.js').at(-1)?.cookie).toBe('');
    await harvestStatic({baseUrl:base+'/',outputRoot,cookie:'secret=target',maxRounds:0});
    expect(await readJsCorpus(join(outputRoot,'js'))).toEqual([]);
    expect(await readFile(join(outputRoot,'secrets.txt'),'utf8')).toBe('');
    const manifest=JSON.parse(await readFile(join(outputRoot,'harvest_manifest.json'),'utf8'));
    expect(manifest.target).toBe(base+'/'); expect(manifest.count).toBe(0); expect(manifest.files.length).toBeGreaterThan(0);
  },15000);
  it("keeps coverage requests across documents and same-URL body changes, merging producer samples",async()=>{
    const {runCoverage}=await import('../src/domain/coverage.js'); const outputRoot=await root();
    await writeFile(join(outputRoot,'param_samples.json'),JSON.stringify([{method:'POST',url:base+'/runtime-only',body:'runtime',sources:['runtime']}])) ;
    const r=await runCoverage({baseUrl:base+'/coverage-a',outputRoot,routes:['/coverage-a','/coverage-b'],maxClicksPerCategory:1,timeoutMs:10000});
    expect(r.routesVisited).toContain('/coverage-b');
    expect(r.paramSamples.some(p=>p.body==='{"q":"initial"}')).toBe(true);
    expect(r.paramSamples.some(p=>p.body==='{"q":"velric"}')).toBe(true);
    const file=JSON.parse(await readFile(join(outputRoot,'coverage.json'),'utf8'));
    const ids=file.requests.map((p:any)=>p.requestId); expect(ids.length).toBeGreaterThan(2); expect(new Set(ids).size).toBe(ids.length); expect(ids).toEqual([...ids].sort((a:number,b:number)=>a-b));
    expect(new Set(file.requests.map((p:any)=>p.documentUrl)).size).toBeGreaterThan(1);
    const samples=JSON.parse(await readFile(join(outputRoot,'param_samples.json'),'utf8'));
    expect(samples.some((s:any)=>s.sources.includes('runtime')&&s.url.endsWith('/runtime-only'))).toBe(true);
    expect(samples.some((s:any)=>s.sources.includes('coverage')&&s.body==='{"q":"velric"}')).toBe(true);
  },30000);
  it("isolates screenshot state per URL and stores the actual PNG bytes as evidence",async()=>{
    const {captureScreenshots}=await import('../src/domain/screenshot.js'); const outputRoot=await root();
    const r=await captureScreenshots({urls:[base+'/screenshot-set',base+'/screenshot-check'],outputRoot,concurrency:1,chromiumPath:'/usr/bin/chromium'});
    expect(r.captured).toBe(2); expect(r.entries.find(e=>e.url.endsWith('/screenshot-check'))?.title).toBe('clean');
    expect(wire.filter(w=>w.path==='/screenshot-check').at(-1)?.cookie).toBe('');
    const {EvidenceStore}=await import('../src/domain/graphs.js'); const store=new EvidenceStore(outputRoot); await store.load();
    for (const e of r.entries) { const bytes=await store.get(e.screenshotHash); expect(bytes?.subarray(0,8).toString('hex')).toBe('89504e470d0a1a0a'); expect(bytes?.length).toBe(e.bytes); }
    expect(r.artifacts.some(a=>a.path.endsWith('screenshot_evidence.json'))).toBe(true);
    expect(r.artifacts.filter(a=>a.path.endsWith('.png'))).toHaveLength(2);
    const empty=await captureScreenshots({urls:[],outputRoot,concurrency:1,chromiumPath:'/usr/bin/chromium'}); expect(empty.captured).toBe(0);
    expect(JSON.parse(await readFile(join(outputRoot,'screenshots.json'),'utf8')).entries).toEqual([]);
  },15000);
  it("records runtime transport receipts without overwriting coverage samples and rejects external routes",async()=>{
    const {captureRuntime}=await import('../src/application/runtime.js'); const {withExecution,receipts}=await import('../src/core/execution.js'); const outputRoot=await root();
    await writeFile(join(outputRoot,'param_samples.json'),JSON.stringify([{method:'POST',url:base+'/coverage-only',body:'coverage',sources:['coverage']}])) ;
    let transport:any[]=[];
    const r=await withExecution({tool:'capture_runtime',ledgerRoot:outputRoot},async()=>{const result=await captureRuntime({baseUrl:base+'/coverage-a',outputRoot,routes:['/coverage-b',`http://localhost:${new URL(base).port}/leak`],waitMs:100,perRouteMs:100,recordWs:false});transport=receipts();return result;});
    expect(r.routesVisited).not.toContain(`http://localhost:${new URL(base).port}/leak`);
    expect(transport.some(r=>r.url===base+'/query'&&r.method==='POST'&&r.status===200&&r.complete)).toBe(true);
    const samples=JSON.parse(await readFile(join(outputRoot,'param_samples.json'),'utf8'));
    expect(samples.some((s:any)=>s.sources.includes('coverage')&&s.url.endsWith('/coverage-only'))).toBe(true);
    const doc=JSON.parse(await readFile(join(outputRoot,'runtime_api.json'),'utf8'));
    expect(doc.mode).toBe('passive'); expect(doc.requests.length).toBeGreaterThan(0);
    const manifest=JSON.parse(await readFile(join(outputRoot,'runtime_manifest.json'),'utf8')); expect(manifest.target).toBe(base+'/coverage-a');
  },20000);
  it('separates login submission from authentication and detects same-name cookie changes',async()=>{
    const {replayLogin}=await import('../src/domain/loginReplay.js');
    const wrong=await replayLogin({baseUrl:base+'/login-browser',username:'wrong',password:'test',outputRoot:await root(),timeoutMs:3000});
    expect(wrong.submitted).toBe(true); expect((wrong as any).authenticated).toBe(false); expect(wrong.cookieHeader).toBeNull();
    const right=await replayLogin({baseUrl:base+'/login-browser',username:'valid',password:'test',outputRoot:await root(),timeoutMs:3000,loggedInRegex:'AUTHENTICATED_MEMBER'} as any);
    expect((right as any).authenticated).toBe(true); expect(right.cookieHeader).toContain('sid=member');
    const artifact=await readFile(right.artifacts[0]!.path,'utf8'); expect(artifact).not.toContain('sid=member'); expect(artifact).not.toContain('test');
  },20000);
  it('honors sitemap input paths and reports only actual coverage clicks without inferred gate success',async()=>{
    const {buildSiteMap}=await import('../src/domain/siteMap.js'); const outputRoot=await root();
    await writeFile(join(outputRoot,'custom-routes.txt'),'/custom\n'); await writeFile(join(outputRoot,'custom-apis.txt'),'/api/custom\n');
    await writeFile(join(outputRoot,'custom-coverage.json'),JSON.stringify({interactions:[{route:'/custom',kind:'toolbar',label:'search'},{route:'/clicked',kind:'menu',label:'clicked',requestIds:[1]}]}));
    await writeFile(join(outputRoot,'gates_report.json'),JSON.stringify({suggestedConfig:{}}));
    const r=await buildSiteMap({baseUrl:base,outputRoot,routesFile:join(outputRoot,'custom-routes.txt'),apiMergedFile:join(outputRoot,'custom-apis.txt'),coverageFile:join(outputRoot,'custom-coverage.json')});
    expect(r.frontendRoutes).toEqual(['/custom']); expect(r.apis).toContain('/api/custom'); expect(r.routesVerifiedByClick).toEqual(['/clicked']); expect(r.routeGuardStrategy).toEqual([]);
  });
  it('emits explicit empty permission artifacts instead of reusing stale stubs',async()=>{
    const {buildPermissionTree}=await import('../src/application/permTreeService.js'); const outputRoot=await root(),jsDir=join(outputRoot,'js'); await mkdir(jsDir); await writeFile(join(jsDir,'nothing.js'),'const noPermissions=true;');
    await writeFile(join(outputRoot,'permissions_tree.json'),'[{"stale":true}]');
    const r=await buildPermissionTree({jsDir,outputRoot}); expect(r.entries).toBe(0); expect(r.tree).toEqual([]);
    expect(JSON.parse(await readFile(join(outputRoot,'permissions_tree.json'),'utf8'))).toEqual([]);
    expect(JSON.parse(await readFile(join(outputRoot,'permission_manifest.json'),'utf8')).count).toBe(0);
  });
  it('replaces only its own parameter samples and keeps coalesced source attribution',async()=>{
    const {mergeBrowserSamples}=await import('../src/application/harvest.js'); const outputRoot=await root(); const row={method:'POST',url:base+'/query',body:'{"q":1}'};
    await mergeBrowserSamples(outputRoot,base,'runtime',[row]); await mergeBrowserSamples(outputRoot,base,'coverage',[row]);
    let rows=JSON.parse(await readFile(join(outputRoot,'param_samples.json'),'utf8')); expect(rows).toHaveLength(1); expect(rows[0].sources.sort()).toEqual(['coverage','runtime']);
    await mergeBrowserSamples(outputRoot,base,'coverage',[]); rows=JSON.parse(await readFile(join(outputRoot,'param_samples.json'),'utf8')); expect(rows[0].sources).toEqual(['runtime']);
    await mergeBrowserSamples(outputRoot,base+'/other-target','coverage',[]); rows=JSON.parse(await readFile(join(outputRoot,'param_samples.json'),'utf8')); expect(rows).toEqual([]);
  });
  it('does not create transport receipts for browser-blocked cross-origin traffic',async()=>{
    const {captureRuntime}=await import('../src/application/runtime.js'); const {withExecution,receipts}=await import('../src/core/execution.js'); let rows:any[]=[];
    await withExecution({tool:'capture_runtime'},async()=>{await captureRuntime({baseUrl:base+'/scope',outputRoot:await root(),routes:[],maxRoutes:0,waitMs:100,recordWs:false});rows=receipts();});
    expect(rows.some(r=>new URL(r.url).hostname==='localhost')).toBe(false);
    expect(rows.some(r=>r.url===base+'/local.js')).toBe(true);
  },15000);
  it("keeps passive fetch Request metadata, binary XHR callbacks and native SSE", async () => {
    const ctx = await browser.newContext();
    try {
      await ctx.addInitScript(buildPreloadScript(DEFAULT_HOOK_CONFIG));
      const page = await ctx.newPage(); await page.goto(base);
      const result = await page.evaluate(`(async () => {
        const r = await fetch(new Request('/api'.startsWith('/') ? location.origin + '/api' : '/api', {method:'POST', headers:{'x-business':'kept'}, body:'{"slot":2}'}));
        const json = await r.json();
        const xhrs = await Promise.all(['arraybuffer','blob','json','document','text',''].map(type => new Promise(resolve => {
          const x = new XMLHttpRequest(); x.open('GET', '/api'); x.responseType = type;
          let called = false; x.onreadystatechange = () => { if (x.readyState === 4) called = true; };
          x.onloadend = () => resolve({type, called}); x.send();
        })));
        const event = await new Promise(resolve => { const es = new EventSource('/events'); es.onmessage = e => { es.close(); resolve(e.data); }; setTimeout(() => { es.close(); resolve('missing'); }, 1000); });
        await new Promise(r => setTimeout(r, 50));
        return {json, xhrs, event, details:window.__API_RECON_DETAIL__};
      })()` ) as any;
      expect(result.json).toEqual({ code: 401, message: "unauthorized", data: null });
      expect(result.xhrs.every((x:any) => x.called)).toBe(true);
      expect(result.event).toBe("fixture-message");
      const post = result.details.find((d:any) => d.method === "POST");
      expect(post?.reqBody).toBe('{"slot":2}');
      expect(post?.reqHeaders?.["x-business"]).toBe("kept");
    } finally { await ctx.close(); }
  }, 15000);
});
