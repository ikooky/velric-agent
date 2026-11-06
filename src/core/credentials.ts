import { createHash } from "node:crypto";
const CREDENTIAL = /^(?:cookie|authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)$/i;
const TOKEN_FIELD = /^(?:access_?token|refresh_?token|id_?token|auth_?token|api_?key|apikey|token|jwt|session_?token)$/i;
const HOP = /^(?:host|content-length|connection|keep-alive|transfer-encoding|upgrade|te|trailer|proxy-connection|if-none-match|if-modified-since)$/i;

export const normalizeHeaders = (headers: Readonly<Record<string, string>> = {}): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) out[name.toLowerCase()] = value;
  return out;
};
export const stripCredentials = (headers: Readonly<Record<string, string>> = {}): Record<string, string> =>
  Object.fromEntries(Object.entries(normalizeHeaders(headers)).filter(([name]) => !CREDENTIAL.test(name)));
export const credentialHeaders = (value: string): Record<string, string> => {
  if (!value.trim()) return {};
  if (/^authorization\s*:/i.test(value)) return { authorization: value.replace(/^authorization\s*:\s*/i, "") };
  if (/^bearer\s+/i.test(value)) return { authorization: value };
  return { cookie: value.replace(/^cookie\s*:\s*/i, "") };
};
export const principalHash = (headers: Readonly<Record<string, string>> = {}): string => {
  const items = Object.entries(normalizeHeaders(headers)).filter(([name]) => CREDENTIAL.test(name)).sort(([a],[b])=>a.localeCompare(b));
  return items.length ? createHash("sha256").update(JSON.stringify(items)).digest("hex") : "anonymous";
};
export const sameOrigin = (a: string, b: string): boolean => {
  try { return new URL(a).origin === new URL(b).origin; } catch { return false; }
};
export const credentialScope = (url: string, origin: string, headers: Readonly<Record<string, string>> = {}): Record<string,string> =>
  sameOrigin(url, origin) ? normalizeHeaders(headers) : stripCredentials(headers);

export interface RecordedRequest { url: string; headers?: Readonly<Record<string,string>>; body?: string | Uint8Array }
export interface RoleOverride {
  credential?: string;
  headers?: Readonly<Record<string,string>>;
  query?: Readonly<Record<string,string|null>>;
  body?: Readonly<Record<string,unknown>>;
  anonymous?: boolean;
}
const patchBody = (source: string, patches: Readonly<Record<string,unknown>>, removeTokens: boolean): string => {
  let value: unknown;
  try { value = JSON.parse(source); } catch {
    const form = new URLSearchParams(source);
    if (!source.includes("=")) {
      if (Object.keys(patches).length > 0) throw Object.assign(new Error("non-form body cannot carry patches"),{code:"unmapped_credential"});
      return source;
    }
    if (removeTokens) for (const name of [...form.keys()]) if (TOKEN_FIELD.test(name)) form.delete(name);
    for (const [name,val] of Object.entries(patches)) { if (val === null) form.delete(name); else form.set(name,String(val)); }
    return form.toString();
  }
  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") return Object.fromEntries(Object.entries(node).filter(([name])=>!removeTokens || !TOKEN_FIELD.test(name)).map(([name,val])=>[name,walk(val)]));
    return node;
  };
  const result = walk(value);
  if (result && typeof result === "object" && !Array.isArray(result)) {
    for (const [name,val] of Object.entries(patches)) { if (val===null) delete (result as Record<string,unknown>)[name]; else (result as Record<string,unknown>)[name]=val; }
  } else if (Object.keys(patches).length > 0) {
    // Array root / scalar body: silently keeping the recorded bytes would be a
    // masked no-op — surface it instead.
    throw Object.assign(new Error("json body root is not a patchable object"),{code:"unmapped_credential"});
  }
  return JSON.stringify(result);
};
export const roleRequest = (recorded: RecordedRequest, override: RoleOverride): {url:string;headers:Record<string,string>;body?:string|Uint8Array} => {
  const url = new URL(recorded.url);
  if (override.anonymous) for (const name of [...url.searchParams.keys()]) if (TOKEN_FIELD.test(name)) url.searchParams.delete(name);
  for (const [name,val] of Object.entries(override.query??{})) { if(val===null)url.searchParams.delete(name);else url.searchParams.set(name,val); }
  const headers = Object.fromEntries(Object.entries(stripCredentials(recorded.headers)).filter(([name])=>!HOP.test(name)));
  // Hop-by-hop filtering applies to BOTH sources: a caller override must not
  // re-introduce connection/content-length/transfer-encoding and corrupt framing.
  if (!override.anonymous) Object.assign(headers,credentialHeaders(override.credential??""),Object.fromEntries(Object.entries(normalizeHeaders(override.headers)).filter(([name])=>!HOP.test(name))));
  let body = recorded.body;
  if (body && (override.anonymous || override.body)) {
    if (typeof body!=="string") throw Object.assign(new Error("binary identity carriers require an explicit request mapping"),{code:"unmapped_credential"});
    body = patchBody(body, override.body??{},override.anonymous===true);
  }
  return {url:url.href,headers,...(body===undefined?{}:{body})};
};

interface Cookie { name:string;value:string;domain:string;hostOnly:boolean;path:string;secure:boolean;expires:number|null }
export class SessionJar {
  private readonly cookies = new Map<string,Cookie>();
  private readonly bearers = new Map<string,string>();
  update(url: string, rows: readonly string[]): void {
    const u=new URL(url);
    for(const row of rows){
      const [pair,...attributes]=row.split(";");const equal=pair?.indexOf("=")??-1;if(equal<1)continue;
      const name=pair!.slice(0,equal).trim(),value=pair!.slice(equal+1).trim();
      const props=new Map(attributes.map(part=>{const i=part.indexOf("=");return i<0?[part.trim().toLowerCase(),""]:[part.slice(0,i).trim().toLowerCase(),part.slice(i+1).trim()];}));
      const explicit=props.get("domain");const domain=(explicit??u.hostname).replace(/^\./,"").toLowerCase();
      if(explicit && u.hostname!==domain && !u.hostname.endsWith("."+domain))continue;
      // Public-suffix guard: a bare TLD Domain (Domain=com) would otherwise be
      // replayed to every host under that suffix (cookie tossing).
      if(explicit && (domain.indexOf(".")<0 || domain==="localhost"))continue;
      const defaultPath=u.pathname.slice(0,u.pathname.lastIndexOf("/")+1)||"/";
      const path=props.get("path")?.startsWith("/")?props.get("path")!:defaultPath;
      const expires=props.has("max-age")?Date.now()+Number(props.get("max-age"))*1000:props.has("expires")?Date.parse(props.get("expires")!):null;
      const key=domain+"|"+path+"|"+name;
      if(expires!==null && Number.isFinite(expires) && expires<=Date.now()){this.cookies.delete(key);continue;}
      this.cookies.set(key,{name,value,domain,hostOnly:!explicit,path,secure:props.has("secure"),expires:Number.isFinite(expires)?expires:null});
    }
  }
  header(url:string):string {
    const u=new URL(url);const matches:Cookie[]=[];
    for(const [key,c]of this.cookies){
      if(c.expires!==null && c.expires<=Date.now()){this.cookies.delete(key);continue;}
      if(c.secure && u.protocol!=="https:")continue;
      if(c.hostOnly?u.hostname!==c.domain:u.hostname!==c.domain && !u.hostname.endsWith("."+c.domain))continue;
      if(u.pathname!==c.path && !u.pathname.startsWith(c.path.endsWith("/")?c.path:c.path+"/"))continue;
      matches.push(c);
    }
    return matches.sort((a,b)=>b.path.length-a.path.length).map(c=>c.name+"="+c.value).join("; ");
  }
  setBearer(origin:string,value:string):void {this.bearers.set(new URL(origin).origin,value);}
  headers(url:string):Record<string,string> {const out:Record<string,string>={};const cookie=this.header(url);if(cookie)out.cookie=cookie;const bearer=this.bearers.get(new URL(url).origin);if(bearer)out.authorization="Bearer "+bearer;return out;}
}
