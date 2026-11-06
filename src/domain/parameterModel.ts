import { normalizeHeaders, roleRequest, stripCredentials, type RoleOverride } from "../core/credentials.js";
import { readBlob } from "../core/storage.js";
import { isDeepStrictEqual } from "node:util";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** A request sample retains the entire URL and the original body bytes. */
export interface ParameterRequest {
  readonly url: string;
  readonly method: string;
  readonly headers?: Record<string, string>;
  readonly body?: string | Buffer | null;
}
export interface ParameterSample extends ParameterRequest {
  readonly id: string;
  readonly status: number | null;
}
export interface ParameterSlot {
  readonly in: "body" | "query";
  readonly name: string;
  /** JSON pointer for JSON bodies; decoded parameter name otherwise. */
  readonly path: string;
  readonly occurrence: number;
  readonly value: unknown;
  readonly start: number;
  readonly end: number;
}

const pointerPart = (key: string): string => key.replace(/~/g, "~0").replace(/\//g, "~1");
const asText = (body: string | Buffer | null | undefined): string | null => {
  if (body == null) return null;
  if (typeof body === "string") return body;
  const text = body.toString("utf8");
  return Buffer.from(text).equals(body) ? text : null;
};
const decode = (text: string): string => { try { return decodeURIComponent(text.replace(/\+/g," ")); } catch { return text; } };

/** JSON.parse validates syntax; the scanner only records exact token spans. */
function jsonSlots(text: string): ParameterSlot[] {
  try { JSON.parse(text); } catch { return []; }
  const slots: ParameterSlot[] = [];
  let i=0;
  const space=()=>{ while (/\s/.test(text[i] ?? "") && i<text.length) i++; };
  const string=()=>{ const start=i++; while(i<text.length){ if(text[i]==="\\") i+=2; else if(text[i++]==='"') break; } return JSON.parse(text.slice(start,i)) as string; };
  const value=(path: string, name: string): void => {
    space(); const start=i;
    if(text[i]==="{") { i++; space(); while(text[i]!=="}"){ const key=string(); space(); i++; value(path+"/"+pointerPart(key),key); space(); if(text[i]!==",")break; i++; space(); } i++; }
    else if(text[i]==="["){ i++; space(); let n=0; while(text[i]!=="]"){ value(path+"/"+n,String(n)); n++; space(); if(text[i]!==",")break; i++; } i++; }
    else if(text[i]==='"') string();
    else { while(i<text.length && !/[\s,\]}]/.test(text[i]!))i++; }
    if(path)slots.push({in:"body",name,path,occurrence:0,value:JSON.parse(text.slice(start,i)),start,end:i});
  };
  value("", "");
  return slots;
}
function encodedSlots(text: string, where: "body"|"query", offset=0): ParameterSlot[] {
  const slots: ParameterSlot[]=[]; const counts=new Map<string,number>(); let at=0;
  for(const part of text.split("&")){
    const eq=part.indexOf("="); const name=decode(eq<0?part:part.slice(0,eq));
    if(part){ const occurrence=counts.get(name)??0; counts.set(name,occurrence+1); slots.push({in:where,name,path:name,occurrence,value:decode(eq<0?"":part.slice(eq+1)),start:offset+at,end:offset+at+part.length}); }
    at+=part.length+1;
  }
  return slots;
}
export function parameterSlots(request: ParameterRequest, where: "body"|"query"): ParameterSlot[] {
  if(where==="query"){
    const q=request.url.indexOf("?"); const h=request.url.indexOf("#",q);
    return q<0?[]:encodedSlots(request.url.slice(q+1,h<0?undefined:h),where,q+1);
  }
  const text=asText(request.body); if(text===null)return [];
  const type=Object.entries(request.headers??{}).find(([k])=>k.toLowerCase()==="content-type")?.[1]??"";
  if(/application\/x-www-form-urlencoded/i.test(type))return encodedSlots(text,where);
  return jsonSlots(text);
}
/** Unqualified names must resolve uniquely; repeated query names need an index. */
function locateParameter(request: ParameterRequest, where: "body"|"query", field: string, occurrence?: number): ParameterSlot | null {
  let slots=parameterSlots(request,where).filter(s=>where==="body"&&field.startsWith("/")?s.path===field:s.name===field);
  if(occurrence!==undefined)slots=slots.filter(s=>s.occurrence===occurrence);
  return slots.length===1?slots[0]!:null;
}
export function mutateParameter(request: ParameterRequest, where: "body"|"query", field: string, value: unknown, occurrence?: number): {request:ParameterRequest;slot:ParameterSlot}|null {
  const slot=locateParameter(request,where,field,occurrence); if(!slot)return null;
  const jsonBody=where==="body" && slot.path.startsWith("/");
  const replacement=jsonBody?JSON.stringify(value):encodeURIComponent(slot.name)+"="+encodeURIComponent(String(value));
  if(replacement===undefined)return null;
  if(jsonBody?JSON.stringify(slot.value)===JSON.stringify(value):String(slot.value)===String(value))return null;
  if(where==="query")return {request:{...request,url:request.url.slice(0,slot.start)+replacement+request.url.slice(slot.end)},slot};
  const text=asText(request.body)!; const body=text.slice(0,slot.start)+replacement+text.slice(slot.end);
  return {request:{...request,body:Buffer.isBuffer(request.body)?Buffer.from(body):body},slot};
}

export function removeParameter(request:ParameterRequest,slot:ParameterSlot):ParameterRequest {
  if(slot.in!=="query")throw new Error("only query removal is supported");
  const url=request.url;
  const start=url[slot.start-1]==="&"?slot.start-1:slot.start;
  const end=start===slot.start&&url[slot.end]==="&"?slot.end+1:slot.end;
  let changed=url.slice(0,start)+url.slice(end);
  changed=changed.replace(/\?(?=#|$)/,"");
  return {...request,url:changed};
}
export function injectParameter(request: ParameterRequest, field: string, value: unknown): ParameterRequest | null {
  const text=asText(request.body); if(text===null || field.startsWith("/"))return null;
  let object:unknown; try { object=JSON.parse(text); } catch { return null; }
  if(!object || typeof object!=="object" || Array.isArray(object) || Object.hasOwn(object,field))return null;
  const at=text.lastIndexOf("}"); const prefix=Object.keys(object).length?",":"";
  const body=text.slice(0,at)+prefix+JSON.stringify(field)+":"+JSON.stringify(value)+text.slice(at);
  return {...request,body:Buffer.isBuffer(request.body)?Buffer.from(body):body};
}
/** Strict JSON path/value comparison; presence and truthiness are not proof. */
export function exactResponseValue(body: string, path: string, value: unknown): boolean {
  try {
    const node=JSON.parse(body) as unknown;
    const parts=path.startsWith("/")?path.slice(1).split("/").map(p=>p.replace(/~1/g,"/").replace(/~0/g,"~")):[path];
    let current:unknown=node;
    for(const part of parts){ if(current===null || typeof current!=="object" || !Object.hasOwn(current,part))return false; current=(current as Record<string,unknown>)[part]; }
    return isDeepStrictEqual(current,value);
  } catch { return false; }
}

export function prepareParameterRequest(request:ParameterRequest,override?:RoleOverride,extraHeaders?:Record<string,string>):ParameterRequest {
  const h=normalizeHeaders(request.headers);
  const connection=(h.connection??"").split(",").map(k=>k.trim().toLowerCase());
  const headers=Object.fromEntries(Object.entries(h).filter(([k])=>!connection.includes(k)&&!/^(host|content-length|connection|keep-alive|transfer-encoding|upgrade|te|trailer|proxy-connection|if-none-match|if-modified-since)$/i.test(k)));
  const extras=normalizeHeaders(extraHeaders);
  const hasCredentialExtra=Object.keys(extras).some(k=>!Object.hasOwn(stripCredentials(extras),k));
  if(!override&&!hasCredentialExtra)return {...request,headers:{...headers,...extras}};
  const chosen=override??{};
  let body: string|Buffer|undefined=request.body??undefined;
  if(Buffer.isBuffer(body)){
    const text=asText(body); if(text===null)throw new Error("binary credentials require an explicit supported body mapping"); body=text;
  }
  // Sanitize every recorded carrier before applying any new identity mapping.
  const clean=roleRequest({url:request.url,headers,body},{anonymous:true});
  const prepared=roleRequest(clean,{...chosen,headers:{...extras,...normalizeHeaders(chosen.headers)}});
  return {...request,url:prepared.url,headers:prepared.headers,body:prepared.body as string|Buffer|undefined};
}

export async function loadParameterSamples(recordRoot: string): Promise<ParameterSample[]> {
  const lines=(await readFile(join(recordRoot,"traffic.ndjson"),"utf8")).split("\n");
  const samples:ParameterSample[]=[];
  for(const [index,line] of lines.entries()){
    if(!line.trim())continue;
    let row: any;
    try { row=JSON.parse(line); } catch { if(index===lines.length-1)continue; throw new Error("invalid traffic record"); }
    if(typeof row.url!=="string"||typeof row.method!=="string"||typeof row.id!=="string")continue;
    if(!/^https?:\/\//i.test(row.url))continue;
    let body:Buffer|undefined;
    if(row.reqBodyHash){
      if(typeof row.reqBodyHash!=="string"||!/^([a-f0-9]{64})$/i.test(row.reqBodyHash))throw new Error("invalid request blob hash");
      const stored=await readBlob(recordRoot,row.reqBodyHash);
      if(stored===null)throw new Error("request blob missing"); body=stored;
    }
    samples.push({id:row.id,method:row.method.toUpperCase(),url:row.url,headers:row.reqHeaders??{},body,status:row.status??null});
  }
  return samples;
}
