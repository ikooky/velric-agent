import { createHash } from "node:crypto";
import { fetchUrl } from "../adapters/http.js";
import { readJson, writeJson, withRootLock } from "../core/storage.js";
import { withExecution } from "../core/execution.js";
import { loadGraph, saveGraph } from "../application/graph.js";
import { EvidenceStore } from "./graphs.js";
import { bindEvidence, getBindings } from "./evidenceBinding.js";

export interface RetestPredicate {
  readonly fixedStatuses?: number[];
  readonly fixedBodyAny?: string[];
  readonly vulnerableBodyAny?: string[];
}
export interface RetestRecord {
  readonly id: string;
  readonly findingId: string;
  readonly ts: string;
  readonly verdict: "reproduced" | "fixed" | "inconclusive";
  readonly request: { method: string; url: string; headers?: Record<string,string>; body?: string };
  readonly observed: { status: number | null; bodySnippet: string; err?: string; complete?: boolean; truncated?: boolean;
    bodyHash?: string; bytes?: number; receiptId?: string; matches?: {predicate:string;value:string;offset:number;snippet:string}[] };
  readonly evidenceHashes?: string[];
  readonly note?: string;
}
export interface FindingRecord {
  readonly id: string;
  readonly name: string;
  readonly severity: "low" | "medium" | "high" | "critical";
  disposition: "pending" | "fixed";
  readonly createdAt: string;
  poc: RetestRecord["request"];
  predicates: RetestPredicate;
  retests: RetestRecord[];
  version?: number;
}
export interface RetestStore { findings: Record<string,FindingRecord> }
const STORE = "retest_store.json";
const validPredicates = (pred: RetestPredicate | undefined): boolean => {
  if (!pred || typeof pred!=="object" || Array.isArray(pred)) return false;
  if (Object.keys(pred).some(k=>!["fixedStatuses","fixedBodyAny","vulnerableBodyAny"].includes(k))) return false;
  if (pred.fixedStatuses!==undefined && (!Array.isArray(pred.fixedStatuses) || !pred.fixedStatuses.every(n=>Number.isInteger(n) && n>=100 && n<=599))) return false;
  for (const values of [pred.fixedBodyAny,pred.vulnerableBodyAny]) {
    if (values!==undefined && (!Array.isArray(values) || !values.every(s=>typeof s==="string" && s.trim().length>0))) return false;
  }
  return (pred.fixedStatuses?.length??0)+(pred.fixedBodyAny?.length??0)+(pred.vulnerableBodyAny?.length??0)>0;
};
const validRequest = (poc: FindingRecord["poc"]): boolean => {
  try { return !!poc && /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(poc.method) && ["http:","https:"].includes(new URL(poc.url).protocol); } catch { return false; }
};
const loadStore = (root: string): Promise<RetestStore> => readJson(root,STORE,()=>({findings:{}}),value=>{
  const st=value as RetestStore;
  return !!st && !!st.findings && typeof st.findings==="object" && !Array.isArray(st.findings) && Object.entries(st.findings).every(([id,f])=>
    f?.id===id && typeof f.name==="string" && validRequest(f.poc) && validPredicates(f.predicates) && Array.isArray(f.retests) &&
    ["fixed","pending"].includes(f.disposition) && (f.version===undefined || Number.isSafeInteger(f.version) && f.version>=0));
});
const saveStore = (root:string,st:RetestStore):Promise<void> => writeJson(root,STORE,st);
const conflict = (): Error => Object.assign(new Error("retest version conflict; re-read and retry"),{code:"version_conflict"});
const signature = (f:FindingRecord):string => JSON.stringify({poc:f.poc,predicates:f.predicates});

export const registerFinding = async (input: {
  root:string; id:string; name:string; severity:FindingRecord["severity"]; poc:FindingRecord["poc"]; predicates?:RetestPredicate; expectedVersion?:number;
}):Promise<{ok:true;created:boolean;version:number}> => withRootLock(input.root,async()=>{
  const st=await loadStore(input.root), prev=st.findings[input.id];
  const predicates=input.predicates??prev?.predicates;
  if (!validPredicates(predicates)) throw new Error("invalid or empty retest predicates");
  if (!input.id.trim() || !validRequest(input.poc)) throw new Error("invalid finding request");
  if (input.expectedVersion!==undefined && input.expectedVersion!==(prev?.version??0)) throw conflict();
  const version=(prev?.version??0)+1;
  st.findings[input.id]={id:input.id,name:input.name,severity:input.severity,disposition:prev?.disposition??"pending",
    createdAt:prev?.createdAt??new Date().toISOString(),poc:structuredClone(input.poc),predicates:structuredClone(predicates!),retests:prev?.retests??[],version};
  await saveStore(input.root,st);
  return {ok:true,created:!prev,version};
});

export const runRetest = async (input: {
  root:string; findingId:string; proxy?:string; timeoutMs?:number; note?:string; maxBytes?:number; allowMutation?:boolean; expectedVersion?:number;
}):Promise<RetestRecord & {disposition:FindingRecord["disposition"];version:number}> => {
  const snapshot=await withRootLock(input.root,async()=>{
    const st=await loadStore(input.root),f=st.findings[input.findingId];
    if(!f)throw new Error(`finding ${input.findingId} not registered`);
    if(input.expectedVersion!==undefined && input.expectedVersion!==(f.version??0))throw conflict();
    if(!["GET","HEAD","OPTIONS"].includes(f.poc.method.toUpperCase()) && input.allowMutation!==true)throw new Error("retest mutation requires allowMutation=true");
    return {finding:f,runId:(await loadGraph(input.root)).runId};
  });
  const f=snapshot.finding;
  const r=await withExecution({tool:"finding_retest",runId:snapshot.runId,ledgerRoot:input.root},()=>fetchUrl(f.poc.url,{
    method:f.poc.method,headers:f.poc.headers,body:f.poc.body,proxy:input.proxy,timeoutMs:input.timeoutMs??15000,maxBytes:input.maxBytes??4*1024*1024,raw:true,redirect:"manual",
  }));
  const bytes=r.rawBuffer??Buffer.from(r.body,"utf8"), body=bytes.toString("utf8");
  const complete=r.complete===true && !r.truncated && !r.error && r.status>=100 && r.status<=599;
  const trustworthy=complete && !(r.status>=300 && r.status<400) && r.status!==429 && r.status<500;
  const matches:NonNullable<RetestRecord["observed"]["matches"]>=[];
  for(const [predicate,values] of [["vulnerableBodyAny",f.predicates.vulnerableBodyAny],["fixedBodyAny",f.predicates.fixedBodyAny]] as const){
    for(const value of values??[]) {const offset=body.indexOf(value);if(offset>=0)matches.push({predicate,value,offset,snippet:body.slice(Math.max(0,offset-80),offset+value.length+80)});}
  }
  let verdict:RetestRecord["verdict"]="inconclusive";
  if(trustworthy){
    if(matches.some(m=>m.predicate==="vulnerableBodyAny"))verdict="reproduced";
    else if(f.predicates.fixedStatuses?.includes(r.status)||matches.some(m=>m.predicate==="fixedBodyAny"))verdict="fixed";
  }
  return withRootLock(input.root,async()=>{
    const st=await loadStore(input.root), current=st.findings[input.findingId];
    if(!current || signature(current)!==signature(f) || input.expectedVersion!==undefined && input.expectedVersion!==(current.version??0))throw conflict();
    const store=new EvidenceStore(input.root);
    const response=await store.put(bytes,"retest-response");
    const id=`rt${current.retests.reduce((max,x)=>Math.max(max,Number(x.id.slice(2))||0),0)+1}`;
    const rec:RetestRecord={id,findingId:current.id,ts:new Date().toISOString(),verdict,request:f.poc,
      observed:{status:r.status||null,bodySnippet:body.slice(0,400),err:r.error,complete,truncated:r.truncated===true,bodyHash:response.hash,bytes:bytes.length,receiptId:r.receiptId,matches},
      evidenceHashes:[response.hash],note:input.note};
    const metadata=await store.put(Buffer.from(JSON.stringify(rec,null,2)),"retest-receipt");
    const bindings=await getBindings(input.root,current.id);
    await bindEvidence({root:input.root,findingId:current.id,expectedVersion:bindings?.version??0,refs:[{hash:response.hash,role:"verification"},{hash:metadata.hash,role:"verification"}]});
    current.retests.push({...rec,evidenceHashes:[response.hash,metadata.hash]});
    if(verdict==="fixed")current.disposition="fixed";
    else if(verdict==="reproduced")current.disposition="pending";
    current.version=(current.version??0)+1;
    const graph=await loadGraph(input.root), finding=graph.findings.find(x=>String(x.id)===current.id);
    if(finding && verdict!=="inconclusive"){finding.disposition=current.disposition;await saveGraph(input.root,graph);}
    await saveStore(input.root,st);
    return {...current.retests.at(-1)!,disposition:current.disposition,version:current.version};
  });
};
export const listRetests = async (root:string):Promise<{findings:{id:string;name:string;severity:string;disposition:string;retests:number;lastVerdict:string|null;version:number}[]}> => {
  const st=await loadStore(root);
  return {findings:Object.values(st.findings).map(f=>({id:f.id,name:f.name,severity:f.severity,disposition:f.disposition,retests:f.retests.length,lastVerdict:f.retests.at(-1)?.verdict??null,version:f.version??0}))};
};
