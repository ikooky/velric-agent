import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { normalizeHeaders, principalHash } from "./credentials.js";
import { withRootLock, readJson, writeJson } from "./storage.js";
export interface RequestReceipt { id:string;runId:string;tool:string;url:string;method:string;status:number|null;requestHash:string|null;responseHash:string|null;principal:string;complete:boolean;at:string;finalUrl?:string|null }
interface Context {tool:string;runId:string;ledgerRoot?:string;receipts:RequestReceipt[];signal?:AbortSignal}
const local=new AsyncLocalStorage<Context>();
export const executionRunId=()=>local.getStore()?.runId??"unbound";
export const executionSignal=()=>local.getStore()?.signal;
export const withExecution=async<T>(input:{tool:string;runId?:string;ledgerRoot?:string;signal?:AbortSignal},run:()=>Promise<T>):Promise<T>=>local.run({tool:input.tool,runId:input.runId??randomUUID(),ledgerRoot:input.ledgerRoot,receipts:[],signal:input.signal},run);
export const recordReceipt=async(input:{url:string;method:string;status:number|null;requestHash?:string|null;responseHash?:string|null;principal?:string;complete:boolean;finalUrl?:string|null}):Promise<RequestReceipt>=>{
 const c=local.getStore();if(!c)throw Object.assign(new Error("no execution context"),{code:"receipt_outside_execution"});
 const receipt:RequestReceipt={id:randomUUID(),runId:c.runId,tool:c.tool,url:input.url,method:input.method.toUpperCase(),status:input.status,requestHash:input.requestHash??null,responseHash:input.responseHash??null,principal:input.principal??"anonymous",complete:input.complete,at:new Date().toISOString(),finalUrl:input.finalUrl};c.receipts.push(receipt);
 if(c.ledgerRoot)await withRootLock(c.ledgerRoot,async()=>{const old=await readJson<RequestReceipt[]>(c.ledgerRoot!,"observation_ledger.json",()=>[]);await writeJson(c.ledgerRoot!,"observation_ledger.json",[...old,receipt]);});
 return receipt;
};
export const receipts=()=>[...(local.getStore()?.receipts??[])];
export const hashRequest=(body?:string|Uint8Array,headers:Record<string,string>={})=>createHash("sha256").update(JSON.stringify({headers:normalizeHeaders(headers),body:body??null})).digest("hex");
export const hashResponse=(body?:string|Uint8Array)=>body===undefined?null:createHash("sha256").update(body).digest("hex");
