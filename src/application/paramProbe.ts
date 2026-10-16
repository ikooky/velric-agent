import { readFile } from "node:fs/promises";
import { writeArtifact } from "../adapters/artifacts.js";
import { paramRequestSample, type MergedEndpoint, type ParamSample } from "../domain/params.js";
import { parameterSlots, prepareParameterRequest, removeParameter, type ParameterRequest } from "../domain/parameterModel.js";
import { sendParameterRequest, stableResponses, successfulResponse, completeResponse, responseFingerprint } from "../domain/parameterVerification.js";
import { type RoleOverride } from "../core/credentials.js";

export interface ParamProbeInput {
  readonly mergedFile:string;
  readonly outputRoot:string;
  readonly baseUrl?:string;
  readonly cookie?:string;
  readonly credentialOverrides?:RoleOverride;
  readonly proxy?:string;
  readonly timeoutMs?:number;
  readonly maxEndpoints?:number;
}
export interface ParamProbeResult {
  readonly probed:number;
  readonly endpointResults:{
    method:string;url:string;baseline:{status:number;bytes:number;sha256:string};
    params:{name:string;occurrence?:number;removedStatus:number|null;delta:"same"|"status"|"body"|"error"}[];
  }[];
  readonly skipped:{method:string;url:string;reason:string}[];
  readonly artifacts:{path:string;bytes:number}[];
  readonly skippedRelativeEndpoints:number;
}
export const probeParams = async (input:ParamProbeInput):Promise<ParamProbeResult> => {
  const data:unknown=JSON.parse(await readFile(input.mergedFile,"utf8"));
  if(!Array.isArray(data))throw new Error("merged endpoints must be an array");
  const targets=(data as MergedEndpoint[]).filter(e=>e.method?.toUpperCase()==="GET"&&Array.isArray(e.fields)&&e.fields.some(f=>f.in==="query")).slice(0,input.maxEndpoints??10);
  const endpointResults:ParamProbeResult["endpointResults"]=[];
  const skipped:ParamProbeResult["skipped"]=[]; let skippedRelativeEndpoints=0;
  const opts={proxy:input.proxy,timeoutMs:input.timeoutMs??8000};
  for(const ep of targets){
    let candidates:readonly ParamSample[]=ep.requestSamples??[];
    // A legacy artifact can still carry a complete URL with real query values.
    if(!candidates.length&&ep.path.includes("?"))candidates=[{method:ep.method,url:ep.path}];
    if(!candidates.length){skipped.push({method:ep.method,url:ep.path,reason:"no request sample with real parameter values"});continue;}
    let request:ParameterRequest|undefined;
    let skipRelative=false;
    for(const sample of candidates){
      if(sample.status!=null&&(sample.status<200||sample.status>=300))continue;
      if(!/^https?:\/\//i.test(sample.url)&&!input.baseUrl){skipRelative=true;continue;}
      let resolved:string;try {resolved=new URL(sample.url,input.baseUrl).href;}catch{continue;}
      const original=paramRequestSample({...sample,url:resolved});
      if(!parameterSlots(original,"query").length)continue;
      const override=input.credentialOverrides||input.cookie!==undefined?{credential:input.cookie===undefined?undefined:"Cookie: "+input.cookie,...input.credentialOverrides}:undefined;
      request=prepareParameterRequest(original,override);break;
    }
    if(!request){if(skipRelative)skippedRelativeEndpoints++;skipped.push({method:ep.method,url:ep.path,reason:skipRelative?"relative sample requires baseUrl":"no successful usable request sample"});continue;}
    const base=await sendParameterRequest(request,opts);
    if(!successfulResponse(base)){skipped.push({method:ep.method,url:ep.path,reason:`invalid baseline (${base.status})`});continue;}
    const repeat=await sendParameterRequest(request,opts);
    if(!successfulResponse(repeat)||!stableResponses(base,repeat)){skipped.push({method:ep.method,url:ep.path,reason:"invalid or unstable baseline"});continue;}
    const params:ParamProbeResult["endpointResults"][number]["params"]=[];
    for(const slot of parameterSlots(request,"query").filter(s=>ep.fields.some(f=>f.in==="query"&&f.name===s.name))){
      const r=await sendParameterRequest(removeParameter(request,slot),opts);
      params.push({name:slot.name,occurrence:slot.occurrence,removedStatus:completeResponse(r)?r.status:null,delta:!completeResponse(r)?"error":r.status!==base.status?"status":responseFingerprint(r)!==responseFingerprint(base)?"body":"same"});
    }
    endpointResults.push({method:request.method,url:request.url,baseline:{status:base.status,bytes:base.bytes,sha256:base.sha256},params});
  }
  const result={probed:endpointResults.length,endpointResults,skipped,skippedRelativeEndpoints};
  const art=await writeArtifact(input.outputRoot,"param_probe.json",JSON.stringify(result,null,2));
  return {...result,artifacts:[art]};
};
