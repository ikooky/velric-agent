import { randomBytes } from "node:crypto";
import { fetchUrl, type FetchOptions, type FetchResult } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { normalizeHeaders, type RoleOverride } from "../core/credentials.js";
import { prepareParameterRequest, type ParameterRequest } from "./parameterModel.js";
import { completeResponse, responseFingerprint, successfulResponse, stableResponses } from "./parameterVerification.js";

export interface HiddenParamInput {
  readonly url:string;
  readonly outputRoot:string;
  readonly in?:"query"|"cookie"|"header";
  readonly words?:readonly string[];
  readonly learn?:boolean;
  readonly method?:string;
  readonly body?:string;
  readonly headers?:Record<string,string>;
  readonly cookie?:string;
  readonly credentialOverrides?:RoleOverride;
  readonly proxy?:string;
  readonly timeoutMs?:number;
  readonly maxWords?:number;
  readonly bucketSize?:number;
  /** Includes calibration, buckets, confirmations and junk controls; no hidden retries. */
  readonly maxRequests?:number;
  /** Authorize non-read-only methods, including their baseline. */
  readonly apply?:boolean;
}
export interface HiddenParamResult {
  readonly probed:number;
  readonly requests:number;
  readonly found:{readonly param:string;readonly in:"query"|"cookie"|"header";readonly evidence:string}[];
  readonly unknown:{readonly param?:string;readonly reason:string}[];
  readonly note?:string;
  readonly artifacts:{path:string;bytes:number}[];
}
const BUILTIN_WORDS=[
  "debug","test","dev","stage","internal","admin","debug_flag","verbose","trace","log_level",
  "mock","sandbox","dry_run","preview","draft","experimental","beta","alpha","canary","feature_flag",
  "role","roles","isAdmin","is_admin","as_user","user_id","userId","account_id","tenant","tenant_id","org_id","organization_id","impersonate","sudo","act_as","on_behalf_of","grant","scope","scopes",
  "url","redirect","redirect_uri","redirect_url","next","return","returnUrl","return_to","continue","callback","callbackUrl","dest","destination","goto","target","rurl","u",
  "x_forwarded_for","x_forwarded_host","x_original_url","x_rewrite_url","x_override_url","real_ip",
  "file","filename","path","filepath","dir","directory","template","page","include","require","doc","document",
  "format","output","view","theme","lang","locale","currency","region","timezone","sort","order","filter","fields","select","limit","offset","page_size","cursor","since","until",
  "process","execute","run","eval","exec","render","parse","transform","convert","import","export","old","new","v1","v2","version","api_version","legacy","compat","fallback","backup","copy",
  "access_token","refresh_token","id_token","code","state","nonce","client_id","client_secret","api_key","apikey",
] as const;
const learnWords=(text:string):string[]=>[...new Set(text.match(/\b[a-z][A-Za-z0-9_]{2,23}\b/g)??[])].slice(0,200);
export const mineHiddenParams=async(input:HiddenParamInput):Promise<HiddenParamResult>=>{
  const where=input.in??"query";
  const maxRequests=Math.max(0,Math.floor(input.maxRequests??200));
  const method=(input.method??"GET").toUpperCase();
  const headers=normalizeHeaders(input.headers);if(input.cookie!==undefined)headers.cookie=input.cookie;
  const base=prepareParameterRequest({url:input.url,method,headers,body:input.body},input.credentialOverrides);
  const found:HiddenParamResult["found"]=[],unknown:HiddenParamResult["unknown"]=[];
  let requests=0,probed=0;
  const finish=async(note?:string):Promise<HiddenParamResult>=>{
    const value={probed,requests,found,unknown,...(note?{note}:{})};
    const art=await writeArtifact(input.outputRoot,"hidden_params.json",JSON.stringify(value,null,2));return {...value,artifacts:[art]};
  };
  if(!["GET","HEAD","OPTIONS"].includes(method)&&input.apply!==true)return finish("dry-run: non-read-only method requires apply=true");
  const send=async(names:readonly string[]):Promise<FetchResult|null>=>{
    if(requests>=maxRequests)return null;
    const u=new URL(base.url); const h={...base.headers};
    for(const name of names){if(where==="query")u.searchParams.set(name,"1");else if(where==="header")h[name.toLowerCase()]="1";else h.cookie=(h.cookie?h.cookie+"; ":"")+name+"=1";}
    // Same cache-buster name, different values: all request shapes have an equal noise source.
    if(!u.searchParams.has("fcbz"))u.searchParams.set("fcbz",randomBytes(6).toString("hex"));
    requests++; if(names.length)probed++;
    const opts={method,headers:h,body:base.body??undefined,proxy:input.proxy,timeoutMs:input.timeoutMs??8000,redirect:"manual",maxAttempts:1} as FetchOptions;
    return fetchUrl(u.href,opts);
  };
  const b1=await send([]),b2=await send([]);
  if(!b1||!b2)return finish("request budget exhausted during baseline");
  if(!successfulResponse(b1)||!successfulResponse(b2))return finish("invalid baseline: successful complete responses required");
  if(!stableResponses(b1,b2))return finish("unstable baseline: differential aborted");
  const baseline=responseFingerprint(b1);
  const existing=new Set(where==="query"?[...new URL(base.url).searchParams.keys()]:where==="header"?Object.keys(base.headers??{}):(base.headers?.cookie??"").split(";").map(p=>p.split("=")[0]!.trim()));
  const candidates=[...new Set([...(input.words??[]),...BUILTIN_WORDS,...(input.learn===false?[]:learnWords(b1.body))])].filter(w=>/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(w)&&w!=="fcbz"&&!existing.has(where==="header"?w.toLowerCase():w)).slice(0,input.maxWords??300);
  const used=new Set([...candidates,...existing,"fcbz"]);
  const junkFor=(name:string):string=>{let value=name.split("").reverse().join("");while(value===name||used.has(value))value="p_"+randomBytes(8).toString("hex");used.add(value);return value;};
  const valid=(r:FetchResult|null):r is FetchResult=>r!==null&&completeResponse(r)&&r.status<500&&r.status!==429;
  const check=async(name:string,first:FetchResult):Promise<void>=>{
    const junk=junkFor(name);
    const control=await send([]),again=await send([name]),negative=await send([junk]),end=await send([]);
    if(!valid(control)||!valid(again)||!valid(negative)||!valid(end)){unknown.push({param:name,reason:"confirmation or negative control invalid / budget exhausted"});return;}
    if(responseFingerprint(control)!==baseline||responseFingerprint(end)!==baseline){unknown.push({param:name,reason:"baseline drift during confirmation"});return;}
    if(responseFingerprint(again)===baseline||responseFingerprint(again)!==responseFingerprint(first)){unknown.push({param:name,reason:"positive difference did not reproduce"});return;}
    if(responseFingerprint(negative)!==baseline){unknown.push({param:name,reason:"junk control also changes response"});return;}
    found.push({param:name,in:where,evidence:`stable baseline, repeated exact differential, distinct junk control (${junk}) matched baseline; input recognition only`});
  };
  const bucketSize=Math.max(1,Math.floor(input.bucketSize??1));
  const queue:string[][]=[];for(let i=0;i<candidates.length;i+=bucketSize)queue.push(candidates.slice(i,i+bucketSize));
  while(queue.length&&requests<maxRequests){
    const bucket=queue.shift()!;const r=await send(bucket);
    if(!valid(r)){unknown.push({param:bucket.join(","),reason:"candidate response invalid"});continue;}
    if(responseFingerprint(r)===baseline)continue;
    if(bucket.length===1){await check(bucket[0]!,r);continue;}
    const mid=Math.floor(bucket.length/2);queue.push(bucket.slice(0,mid),bucket.slice(mid));
  }
  return finish(queue.length?"request budget exhausted; untested candidates remain":undefined);
};
