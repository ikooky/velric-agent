import { parameterSlots, type ParameterRequest } from "./parameterModel.js";

export interface ParamSample {
  readonly method:string;
  readonly url:string;
  readonly action?:string;
  readonly body?:string|null;
  readonly query?:string|null;
  readonly headers?:Record<string,string>;
  readonly status?:number|null;
}
export interface MergedParam {
  readonly name:string;
  readonly in:"body"|"query";
  /** Exact request samples containing this field; duplicates in one sample count once. */
  readonly samples:number;
  readonly totalSamples:number;
  readonly confidence:"high"|"medium"|"low"|"pending";
}
export interface MergedEndpoint {
  readonly method:string;
  readonly path:string;
  readonly fields:MergedParam[];
  readonly sampleCount:number;
  /** Original co-occurring values are retained; never synthesize a union baseline. */
  readonly requestSamples:ParamSample[];
}
const confidenceFor=(hits:number,total:number):MergedParam["confidence"]=>total>=2&&hits===total?"high":hits>0?"medium":"pending";
export function paramRequestSample(sample:ParamSample):ParameterRequest {
  let url=sample.url;
  if(!url.includes("?")&&sample.query){const hash=url.indexOf("#");url=url.slice(0,hash<0?undefined:hash)+"?"+sample.query.replace(/^\?/,"")+(hash<0?"":url.slice(hash));}
  const headers={...sample.headers};
  if(sample.body && !Object.keys(headers).some(k=>k.toLowerCase()==="content-type") && !/^[\s]*[\[{]/.test(sample.body)&&sample.body.includes("="))headers["content-type"]="application/x-www-form-urlencoded";
  return {url,method:sample.method.toUpperCase(),body:sample.body,headers};
}
export const mergeParams = (samples:readonly ParamSample[]):MergedEndpoint[] => {
  interface Aggregate {method:string;path:string;body:Map<string,Set<number>>;query:Map<string,Set<number>>;requestSamples:ParamSample[];}
  const byEndpoint=new Map<string,Aggregate>();
  samples.forEach((sample,index)=>{
    if(!sample||typeof sample.url!=="string"||!sample.url||typeof sample.method!=="string"||!sample.method)return;
    const request=paramRequestSample(sample);
    const path=request.url.split(/[?#]/)[0]!; const method=request.method;
    const key=method+" "+path;
    let agg=byEndpoint.get(key);
    if(!agg){agg={method,path,body:new Map(),query:new Map(),requestSamples:[]};byEndpoint.set(key,agg);}
    agg.requestSamples.push({...sample,url:request.url});
    for(const where of ["body","query"] as const){
      for(const slot of parameterSlots(request,where)){
        // The merge inventory exposes top-level JSON/form/query fields; mutation has exact nested slots.
        if(where==="body"&&slot.path.startsWith("/")&&slot.path.slice(1).includes("/"))continue;
        const map=agg[where]; let hits=map.get(slot.name); if(!hits){hits=new Set();map.set(slot.name,hits);}hits.add(index);
      }
    }
  });
  return [...byEndpoint.values()].map(agg=>({
    method:agg.method,path:agg.path,sampleCount:agg.requestSamples.length,requestSamples:agg.requestSamples,
    fields:(["body","query"] as const).flatMap(where=>[...agg[where]].map(([name,hits])=>({name,in:where,samples:hits.size,totalSamples:agg.requestSamples.length,confidence:confidenceFor(hits.size,agg.requestSamples.length)}))).sort((a,b)=>a.name.localeCompare(b.name)||a.in.localeCompare(b.in)),
  })).sort((a,b)=>a.path.localeCompare(b.path)||a.method.localeCompare(b.method));
};
