import { captureVerification, evaluateVerification, sendParameterRequest, completeResponse, responseFingerprint, successfulResponse, type ParameterVerification, type ParameterProof } from "./parameterVerification.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { type RoleOverride } from "../core/credentials.js";
import { loadParameterSamples, mutateParameter, prepareParameterRequest, type ParameterRequest } from "./parameterModel.js";

export interface ReplayExchange {
  readonly id: string;
  readonly method: string;
  readonly url: string;
  readonly reqHeaders: Record<string, string>;
  readonly reqBody: string | Buffer | null;
  readonly baselineStatus: number | null;
  readonly baselineBodyHash: string | null;
}
export interface TamperRule {
  /** A unique field name or an exact JSON pointer for nested body slots. */
  readonly field: string;
  readonly in: "body" | "query";
  readonly occurrence?: number;
  readonly value: string | number | boolean | null;
  readonly label: string;
}
export interface ReplayInput {
  readonly recordRoot: string;
  readonly outputRoot: string;
  readonly exchangeIds?: readonly string[];
  readonly rules: readonly TamperRule[];
  readonly cookie?: string;
  readonly credential?: string;
  readonly credentialOverrides?: RoleOverride;
  readonly extraHeaders?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxExchanges?: number;
  /** Explicitly authorizes baseline and tampered replays. Default: zero requests. */
  readonly applyTamper?: boolean;
  readonly verification?: ParameterVerification;
}
export interface ReplayOutcome {
  readonly exchangeId: string;
  readonly method: string;
  readonly url: string;
  readonly rule: string;
  readonly field: string;
  readonly value: string;
  readonly baselineStatus: number | null;
  readonly replayStatus: number;
  readonly verdict: "behavior-change" | "persisted-change" | "permission-change" | "rejected" | "same-response" | "error" | "skip" | "dry-run";
  readonly outcome:"confirmed"|"lead"|"unproven";
  readonly fieldPath?:string;
  readonly verification?:ParameterProof;
  readonly contentChanged: boolean;
}
export interface ReplayResult {
  readonly replayed: number;
  readonly outcomes: ReplayOutcome[];
  readonly accepted: ReplayOutcome[];
  readonly leads: ReplayOutcome[];
  readonly artifacts: { path: string; bytes: number }[];
}
const DEFAULT_RULES: readonly TamperRule[] = [
  {field:"price",in:"body",value:0.01,label:"price=0.01"},
  {field:"amount",in:"body",value:0.01,label:"amount=0.01"},
  {field:"total",in:"body",value:0.01,label:"total=0.01"},
  {field:"quantity",in:"body",value:-1,label:"quantity=-1"},
  {field:"qty",in:"body",value:-1,label:"qty=-1"},
  {field:"count",in:"body",value:-1,label:"count=-1"},
  {field:"discount",in:"body",value:100,label:"discount=100"},
  {field:"step",in:"body",value:999,label:"step-skip"},
  {field:"status",in:"body",value:"paid",label:"status=paid"},
  {field:"role",in:"body",value:"admin",label:"role=admin"},
  {field:"is_admin",in:"body",value:true,label:"is_admin=true"},
];
const fp=(r:{status:number;sha256:string})=>`${r.status}:${r.sha256}`;
export const replayTamper = async (input: ReplayInput): Promise<ReplayResult> => {
  const exchanges=(await loadParameterSamples(input.recordRoot))
    .filter(e=>input.exchangeIds?input.exchangeIds.includes(e.id):["POST","PUT","PATCH"].includes(e.method))
    .slice(0,input.maxExchanges??20);
  const rules=input.rules.length?input.rules:DEFAULT_RULES;
  const outcomes:ReplayOutcome[]=[];
  let replayed=0;
  for(const e of exchanges){
    const override=input.credentialOverrides||input.credential!==undefined||input.cookie!==undefined?{credential:input.credential??(input.cookie===undefined?undefined:"Cookie: "+input.cookie),...input.credentialOverrides}:undefined;
    const request=prepareParameterRequest(e,override,input.extraHeaders);
    const mutations=rules.flatMap(rule=>{const mutation=mutateParameter(request,rule.in,rule.field,rule.value,rule.occurrence);return mutation?[{rule,...mutation}]:[];});
    if(!mutations.length)continue;
    if(input.applyTamper!==true){
      for(const {rule} of mutations)outcomes.push({exchangeId:e.id,method:e.method,url:e.url,rule:rule.label,field:rule.field,value:String(rule.value),baselineStatus:e.status,replayStatus:-1,verdict:"dry-run",outcome:"unproven",contentChanged:false});
      continue;
    }
    const opts={proxy:input.proxy,timeoutMs:input.timeoutMs??10000};
    const send=(req:ParameterRequest)=>sendParameterRequest(req,opts);
    const live=await send(request); replayed++;
    if(!successfulResponse(live))continue;
    for(const {rule,request:changed,slot} of mutations){
      const before=input.verification?await captureVerification(input.verification,request,opts):[];
      const r=await send(changed);
      const after=input.verification&&successfulResponse(r)?await captureVerification(input.verification,request,opts):[];
      const verification=input.verification?evaluateVerification(input.verification,request,before,after,slot.path,rule.value):undefined;
      const contentChanged=completeResponse(r)&&responseFingerprint(r)!==responseFingerprint(live);
      const verdict:ReplayOutcome["verdict"]=verification?.confirmed?(verification.kind==="re-read"?"persisted-change":"permission-change"):!completeResponse(r)||r.status>=500||r.status===429?"error":successfulResponse(r)&&contentChanged?"behavior-change":r.status>=400&&r.status<500?"rejected":"same-response";
      outcomes.push({exchangeId:e.id,method:e.method,url:e.url,rule:rule.label,field:rule.field,fieldPath:slot.path,value:String(rule.value),baselineStatus:live.status,replayStatus:r.status,verdict,outcome:verification?.confirmed?"confirmed":verdict==="behavior-change"?"lead":"unproven",verification,contentChanged});
    }
  }
  const accepted=outcomes.filter(o=>o.outcome==="confirmed");
  const leads=outcomes.filter(o=>o.outcome==="lead");
  const art=await writeArtifact(input.outputRoot,"replay_tamper.json",JSON.stringify({replayed,outcomes,accepted,leads},null,2));
  return {replayed,outcomes,accepted,leads,artifacts:[art]};
};
