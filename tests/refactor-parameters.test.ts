import { describe, it, expect, afterEach } from "vitest";
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { replayTamper } from "../src/domain/replayTamper.js";
import { probeMassAssign } from "../src/domain/massAssign.js";
import { mineHiddenParams } from "../src/domain/hiddenParams.js";
import { mergeParams } from "../src/domain/params.js";
import { probeParams } from "../src/application/paramProbe.js";

const scratch = process.env.TMPDIR ?? "/root/.hermes/cache/scratch";
const roots: string[] = [];
const root = async () => { const r = await mkdtemp(join(scratch, "param-test-")); roots.push(r); return r; };
async function recording(body: string | Buffer, url = "http://parameters.invalid/write?qty=2", headers: Record<string,string> = {}) {
  const r = await root();
  const hash = createHash("sha256").update(body).digest("hex");
  await mkdir(join(r, "blobs", hash.slice(0,2)), {recursive:true});
  await writeFile(join(r, "blobs", hash.slice(0,2), hash + ".bin"), body);
  await writeFile(join(r,"traffic.ndjson"), JSON.stringify({id:"e1",method:"POST",url,status:200,reqHeaders:headers,reqBodyHash:hash,respBodyHash:null})+"\n");
  return r;
}
const original = getGlobalDispatcher();
let agent: MockAgent | undefined;
function mock(reply: (options: any) => {statusCode:number;data:string}) {
  agent = new MockAgent(); agent.disableNetConnect();
  const current=agent;
  // Undici may expose request bodies as async iterables to dispatchers. Buffer
  // those exact bytes before the MockAgent's synchronous response callback.
  setGlobalDispatcher({dispatch(options:any,handler:any){
    void (async()=>{let body=options.body;if(body!=null&&typeof body!=="string"&&!Buffer.isBuffer(body)&&!(body instanceof Uint8Array)&&body[Symbol.asyncIterator]){const chunks:Buffer[]=[];for await(const chunk of body)chunks.push(Buffer.from(chunk));body=Buffer.concat(chunks);}current.dispatch({...options,body},handler);})().catch(e=>handler.onError?.(e));return true;
  }} as any);
  agent.get("http://parameters.invalid").intercept({path:/.*/,method:/.*/}).reply(reply).persist();
}
afterEach(async () => { setGlobalDispatcher(original); await agent?.close(); agent=undefined; await Promise.all(roots.splice(0).map(r=>rm(r,{recursive:true,force:true}))); });

describe("native parameter mutation and verification", () => {
  it("removes recorded query/body tokens when switching only the credential carrier", async () => {
    const seen:any[]=[];mock(o=>{seen.push({url:String(o.path),body:JSON.parse(Buffer.from(o.body??"").toString())});return {statusCode:200,data:"{}"};});
    const r=await recording('{"token":"HIGH","price":4}',"http://parameters.invalid/write?access_token=HIGH&sort=desc",{cookie:"sid=HIGH"});
    await replayTamper({recordRoot:r,outputRoot:r,applyTamper:true,cookie:"sid=LOW",rules:[{in:"body",field:"price",value:2,label:"price"}]});
    expect(seen.every(o=>!o.url.includes("HIGH")&&!Object.hasOwn(o.body,"token"))).toBe(true);
    expect(seen.every(o=>o.url.includes("sort=desc"))).toBe(true);
  });
  it("does not confirm a re-read that changed to a different value than the injected field", async () => {
    let value:unknown="unset";
    mock(o=>{if(String(o.path).startsWith("/resource"))return {statusCode:200,data:JSON.stringify({isAdmin:value})};const j=JSON.parse(Buffer.from(o.body??"").toString());if(j.isAdmin)value=false;return {statusCode:200,data:JSON.stringify(j)};});
    const r=await recording('{"name":"reader"}');
    const out=await probeMassAssign({recordRoot:r,outputRoot:r,apply:true,fields:["isAdmin"],verification:{kind:"re-read",request:{url:"http://parameters.invalid/resource"},responsePath:"/isAdmin",expectedValue:false,policy:{principal:"reader",resource:"account:self",expected:"deny"}}} as any);
    expect(out.sinks).toEqual([]);
  });
  it("bounds actual hidden-miner wire requests including transport retries", async () => {
    let sent=0;mock(o=>{sent++;const u=new URL(String(o.path),"http://parameters.invalid");return {statusCode:u.searchParams.has("debug")?503:200,data:"base"};});
    const r=await root();const out=await mineHiddenParams({url:"http://parameters.invalid/read",outputRoot:r,learn:false,maxWords:1,maxRequests:3} as any);
    expect(sent).toBe(3);
    expect((out as any).requests).toBe(sent);
    expect(out.found).toEqual([]);
  });
  it("does not retain a bisection candidate whose positive confirmation failed, and continues other candidates", async () => {
    let debugCalls=0;
    mock(o=>{const u=new URL(String(o.path),"http://parameters.invalid");const named=[...u.searchParams.keys()].filter(k=>k!=="fcbz");if(named.length===1&&named[0]==="debug"){debugCalls++;return {statusCode:200,data:debugCalls===1?"debug-read":"base"};}return {statusCode:200,data:named.includes("debug")?"debug-read":named.includes("test")?"test-read":"base"};});
    const r=await root();const out=await mineHiddenParams({url:"http://parameters.invalid/read",outputRoot:r,learn:false,maxWords:2,bucketSize:2});
    expect(out.found.map(x=>x.param)).toEqual(["test"]);
    expect((out as any).unknown.some((x:any)=>x.param==="debug")).toBe(true);
  });
  it("keeps echo-only tamper as a lead and confirms only a separately re-read value", async () => {
    let price=4;
    mock(o=>{if(String(o.path).startsWith("/resource"))return {statusCode:200,data:JSON.stringify({price})};const j=JSON.parse(Buffer.from(o.body??"").toString());price=j.price;return {statusCode:200,data:JSON.stringify(j)};});
    const r=await recording('{"price":4}');const rules=[{field:"price",in:"body" as const,value:2,label:"price"}];
    const lead=await replayTamper({recordRoot:r,outputRoot:r,applyTamper:true,rules});
    expect(lead.accepted).toEqual([]);
    expect((lead as any).leads).toHaveLength(1);
    price=4;
    const confirmed=await replayTamper({recordRoot:r,outputRoot:r,applyTamper:true,rules,verification:{kind:"re-read",request:{url:"http://parameters.invalid/resource"},responsePath:"/price",policy:{principal:"buyer",resource:"order:self",expected:"deny"}}} as any);
    expect(confirmed.accepted).toHaveLength(1);
    expect((confirmed.accepted[0] as any).outcome).toBe("confirmed");
  });
  it("requires a distinct valid junk control even for one-word hidden parameter probes", async () => {
    mock(o=>{const u=new URL(String(o.path),"http://parameters.invalid");return {statusCode:200,data:[...u.searchParams.keys()].some(k=>k!=="fcbz")?'changed':'base'};});
    const r=await root();
    const out=await mineHiddenParams({url:"http://parameters.invalid/read",outputRoot:r,learn:false,maxWords:1});
    expect(out.found).toEqual([]);
  });
  it("probes the actual co-occurring values and removes exactly one occurrence without clearing other query data", async () => {
    const seen:string[]=[];mock(o=>{seen.push(String(o.path));const u=new URL(String(o.path),"http://parameters.invalid");return {statusCode:u.searchParams.get("page")==="9"?200:400,data:'{"rows":[1]}'};});
    const r=await root();const file=join(r,"merged.json");
    await writeFile(file,JSON.stringify(mergeParams([{method:"GET",url:"http://parameters.invalid/items?tag%5B%5D=red&tag%5B%5D=blue&page=9&token=sample"}])));
    const out=await probeParams({mergedFile:file,outputRoot:r});
    expect(seen[0]).toBe("/items?tag%5B%5D=red&tag%5B%5D=blue&page=9&token=sample");
    expect(out.probed).toBe(1);
    expect(seen.some(p=>p.includes("tag%5B%5D=blue")&&!p.includes("tag%5B%5D=red"))).toBe(true);
    expect(out.endpointResults[0]?.params.filter(p=>p.name==="tag[]")).toHaveLength(2);
  });
  it("counts exact per-field sample coverage and retains replayable sample values", () => {
    const samples=[{method:"GET",url:"http://parameters.invalid/items?tag%5B%5D=red&tag%5B%5D=blue&page=9"},{method:"GET",url:"http://parameters.invalid/items?tag%5B%5D=green&page=10"},{method:"GET",url:"http://parameters.invalid/items?page=11"}];
    const [ep]=mergeParams(samples);
    expect(ep?.fields.find(f=>f.name==="tag[]")?.confidence).toBe("medium");
    expect(ep?.fields.find(f=>f.name==="tag[]")?.samples).toBe(2);
    expect(ep?.fields.find(f=>f.name==="page")?.confidence).toBe("high");
    expect((ep as any).sampleCount).toBe(3);
    expect((ep as any).requestSamples[0].url).toBe(samples[0]!.url);
  });
  it("replaces all credential carriers and applies explicit query/body mappings last", async () => {
    const seen:any[]=[]; mock(o=>{seen.push({url:String(o.path),headers:o.headers,body:JSON.parse(Buffer.from(o.body??"").toString())});return {statusCode:200,data:'{"ok":true}'};});
    const r=await recording('{"token":"HIGH","price":4}',"http://parameters.invalid/write?access_token=HIGH",{Cookie:"sid=HIGH",Authorization:"Bearer HIGH","X-Api-Key":"HIGH","X-Csrf-Token":"HIGH","Content-Type":"application/json"});
    const {prepareParameterRequest}=await import("../src/domain/parameterModel.js");
    const prepared=prepareParameterRequest({method:"POST",url:"http://parameters.invalid/write?access_token=HIGH",body:'{"token":"HIGH","price":4}',headers:{"Content-Type":"application/json"}},{credential:"Cookie: sid=LOW",query:{access_token:"LOW"},body:{token:"LOW"}});
    expect(JSON.parse(String(prepared.body)),JSON.stringify(prepared)).toEqual({price:4,token:"LOW"});
    const {loadParameterSamples,mutateParameter}=await import("../src/domain/parameterModel.js");
    const samples=await loadParameterSamples(r);
    const req=prepareParameterRequest(samples[0]!,{credential:"Cookie: sid=LOW",query:{access_token:"LOW"},body:{token:"LOW"}});
    expect(mutateParameter(req,"body","price",2),JSON.stringify(req)).not.toBeNull();
    const {sendParameterRequest}=await import("../src/domain/parameterVerification.js");
    const direct=await sendParameterRequest(req);
    expect(direct.status,JSON.stringify({direct,req})).toBe(200);
    const replay=await replayTamper({recordRoot:r,outputRoot:r,applyTamper:true,cookie:"sid=LOW",credentialOverrides:{query:{access_token:"LOW"},body:{token:"LOW"}},rules:[{in:"body",field:"price",value:2,label:"price"}]} as any);
    expect(seen.length,JSON.stringify(replay)).toBeGreaterThanOrEqual(2);
    for(const req of seen){
      const h=Array.isArray(req.headers)?Object.fromEntries(Array.from({length:req.headers.length/2},(_,i)=>[req.headers[i*2],req.headers[i*2+1]])):req.headers;
      expect(h.cookie).toBe("sid=LOW");
      expect(h.authorization).toBeUndefined(); expect(h["x-api-key"]).toBeUndefined(); expect(h["x-csrf-token"]).toBeUndefined();
      expect(req.url).toContain("access_token=LOW"); expect(req.body.token).toBe("LOW");
    }
  });
  it("confirms a persisted field only through an explicit independent re-read with a policy binding", async () => {
    let admin=false; const seen:string[]=[];
    mock(o=>{seen.push(String(o.path)); if(String(o.path).startsWith("/resource"))return {statusCode:200,data:JSON.stringify({isAdmin:admin})}; const body=JSON.parse(Buffer.from(o.body ?? "").toString("utf8")); if(body.isAdmin===true)admin=true; return {statusCode:200,data:JSON.stringify(body)};});
    const r=await recording('{"name":"reader"}');
    const out=await probeMassAssign({recordRoot:r,outputRoot:r,fields:["isAdmin"],apply:true,verification:{kind:"re-read",request:{url:"http://parameters.invalid/resource",method:"GET"},responsePath:"/isAdmin",policy:{principal:"reader",resource:"account:self",expected:"deny"}}} as any);
    expect(out.sinks, JSON.stringify({out,seen})).toHaveLength(1);
    expect((out.sinks[0] as any).verdict).toBe("persisted-change");
    expect((out.sinks[0] as any).outcome).toBe("confirmed");
    expect(seen.filter(p=>p.startsWith("/resource"))).toHaveLength(4);
  });
  it("requires exact injected values and never calls echo-only writes confirmed sinks", async () => {
    const r=await recording('{"name":"reader"}');
    mock(()=>({statusCode:200,data:'{"name":"reader","isAdmin":false}'}));
    const ignored=await probeMassAssign({recordRoot:r,outputRoot:r,fields:["isAdmin"],apply:true});
    expect(ignored.sinks).toEqual([]);
    expect(ignored.outcomes[0]?.verdict).not.toBe("reflected");
    mock(o=>({statusCode:200,data:Buffer.from(o.body ?? "").toString("utf8")}));
    const echo=await probeMassAssign({recordRoot:r,outputRoot:r,fields:["isAdmin"],apply:true});
    expect(echo.sinks).toEqual([]);
    expect((echo as any).leads).toHaveLength(1);
    expect((echo.outcomes[0] as any).outcome).toBe("lead");
  });
  it("preserves every byte of an unrelated binary body during query tamper", async () => {
    const body=Buffer.from([0,255,128,34,10,13,65]); const seen: Buffer[]=[];
    mock(o=>{ seen.push(Buffer.from(o.body ?? "")); return {statusCode:200,data:'{"ok":true}'}; });
    const r=await recording(body);
    await replayTamper({recordRoot:r,outputRoot:r,rules:[{field:"qty",in:"query",value:3,label:"qty"}],applyTamper:true});
    expect(seen.length).toBeGreaterThanOrEqual(2);
    expect(seen.every(b=>b.equals(body))).toBe(true);
  });
  it("does not inventory a body rule when the field is absent (dry-run sends nothing)", async () => {
    let sent=0; mock(()=>{sent++; return {statusCode:200,data:"{}"};});
    const r=await recording('{"qty":2}');
    const out=await replayTamper({recordRoot:r,outputRoot:r,rules:[{field:"price",in:"body",value:0,label:"price"}]});
    expect(out.outcomes).toEqual([]);
    expect(sent).toBe(0);
  });
});
