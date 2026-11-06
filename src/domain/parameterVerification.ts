import { fetchUrl, type FetchOptions, type FetchResult } from "../adapters/http.js";
import { exactResponseValue, type ParameterRequest } from "./parameterModel.js";
import { sameOrigin, principalHash } from "../core/credentials.js";

/** Verification is an explicit read of the same resource/policy, not the write echo. */
export interface ParameterVerification {
  readonly kind: "re-read" | "permission";
  readonly request: { readonly url:string; readonly method?:"GET"|"HEAD"; readonly headers?:Record<string,string> };
  /** Exact response JSON pointer. Defaults to the mutated field pointer. */
  readonly responsePath?: string;
  /** Defaults to the injected/tampered value. */
  readonly expectedValue?: unknown;
  readonly policy: { readonly principal:string; readonly resource:string; readonly expected:"deny" };
}
export interface ParameterProof {
  readonly kind: "re-read" | "permission";
  readonly confirmed:boolean;
  readonly reason:string;
  readonly principal:string;
  readonly resource:string;
  readonly credentialHash:string;
  readonly before: readonly {status:number;sha256:string;complete:boolean}[];
  readonly after: readonly {status:number;sha256:string;complete:boolean}[];
}
export const completeResponse = (r:FetchResult):boolean => r.status>0 && r.complete!==false && r.truncated!==true && !r.error;
export const successfulResponse = (r:FetchResult):boolean => completeResponse(r)&&r.status>=200&&r.status<300&&r.status!==204;
export const responseFingerprint = (r:Pick<FetchResult,"status"|"sha256">):string => `${r.status}:${r.sha256}`;
export const stableResponses = (a:FetchResult,b:FetchResult):boolean => completeResponse(a)&&completeResponse(b)&&responseFingerprint(a)===responseFingerprint(b);
export const sendParameterRequest = (request:ParameterRequest, options:{proxy?:string;timeoutMs?:number}={}):Promise<FetchResult> =>
  fetchUrl(request.url,{...options,method:request.method,headers:request.headers,body:request.body==null?undefined:(typeof request.body==="string"?Buffer.from(request.body):request.body) as unknown as FetchOptions["body"],redirect:"manual"});
function verificationRequest(verification:ParameterVerification, reference:ParameterRequest):ParameterRequest {
  if(!verification.policy?.principal?.trim()||!verification.policy.resource?.trim()||verification.policy.expected!=="deny")throw new Error("verification requires a principal/resource deny policy");
  if(!sameOrigin(verification.request.url,reference.url))throw new Error("verification must target the sample origin");
  if(!["GET","HEAD"].includes(verification.request.method??"GET"))throw new Error("verification must be read-only");
  return {url:verification.request.url,method:verification.request.method??"GET",headers:verification.request.headers??reference.headers};
}
export async function captureVerification(verification:ParameterVerification, reference:ParameterRequest, options:{proxy?:string;timeoutMs?:number}={}):Promise<FetchResult[]> {
  const request=verificationRequest(verification,reference);
  return [await sendParameterRequest(request,options),await sendParameterRequest(request,options)];
}
export function evaluateVerification(verification:ParameterVerification,reference:ParameterRequest,before:readonly FetchResult[],after:readonly FetchResult[],fieldPath:string,value:unknown):ParameterProof {
  const request=verificationRequest(verification,reference);
  const path=verification.responsePath??(fieldPath.startsWith("/")?fieldPath:"/"+fieldPath.replace(/~/g,"~0").replace(/\//g,"~1"));
  const expected=verification.kind==="re-read"?value:Object.hasOwn(verification,"expectedValue")?verification.expectedValue:value;
  let confirmed=false; let reason="verification response invalid or unstable";
  if(before.length===2&&after.length===2&&stableResponses(before[0]!,before[1]!)&&stableResponses(after[0]!,after[1]!)){
    const pre=before[0]!,post=after[0]!;
    const exact=successfulResponse(post)&&exactResponseValue(post.body,path,expected);
    if(verification.kind==="re-read"){
      confirmed=successfulResponse(pre)&&!exactResponseValue(pre.body,path,expected)&&exact;
      reason=confirmed?"independent stable reads changed to the exact value under a declared deny policy":"exact persisted value transition was not established";
    } else {
      confirmed=[401,403].includes(pre.status)&&exact;
      reason=confirmed?"denied permission reference became exact authorized resource content":"permission transition and exact resource content were not established";
    }
  }
  return {kind:verification.kind,confirmed,reason,principal:verification.policy.principal,resource:verification.policy.resource,credentialHash:principalHash(request.headers),before:before.map(r=>({status:r.status,sha256:r.sha256,complete:completeResponse(r)})),after:after.map(r=>({status:r.status,sha256:r.sha256,complete:completeResponse(r)}))};
}
