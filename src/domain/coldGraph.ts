import { createHash } from "node:crypto";
import { readJson, writeJson, withRootLock } from "../core/storage.js";
import type { ExplorationGraph, ExpNode, ExpEdge, Anchor } from "./graphs.js";

export interface ColdParams { readonly coldAfterRounds:number; readonly maxDigestSize:number }
const DEFAULT_COLD_PARAMS:ColdParams={coldAfterRounds:3,maxDigestSize:50};
export interface NodeStamp { readonly id:string; lastTouched:number; version:number; contentHash?:string; touchVersion?:number }
export interface Folded { digests:string[];folded:string[];rescued:string[] }
const canonical=(value:unknown):unknown=>Array.isArray(value)?value.map(canonical):value && typeof value==="object"?
  Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,canonical(v)])):value;
const hash=(value:unknown):string=>createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
export const digestHash=(nodes:ExpNode[],edges:ExpEdge[]=[],anchors:Anchor[]=[]):string=>hash({nodes:[...nodes].sort((a,b)=>a.id.localeCompare(b.id)),edges:[...edges].sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))),anchors:[...anchors].sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)))});
const coldGroups=(coldIds:Set<string>,edges:ExpEdge[]):string[][]=>{
  const parent=new Map([...coldIds].map(id=>[id,id]));
  const find=(id:string):string=>{let cur=id;while(parent.get(cur)!==cur)cur=parent.get(cur)!;return cur;};
  for(const edge of edges)if(parent.has(edge.from)&&parent.has(edge.to))parent.set(find(edge.from),find(edge.to));
  const groups=new Map<string,string[]>();
  for(const id of coldIds){const key=find(id),group=groups.get(key)??[];group.push(id);groups.set(key,group);}
  return [...groups.values()];
};
interface FoldPayload extends Record<string,unknown> {kind:"digest";members:string[];memberNodes:ExpNode[];originalEdges:ExpEdge[];originalAnchors:Anchor[];hash:string;round:number}
const payload=(n:ExpNode):FoldPayload|null=>n.payload?.kind==="digest"?n.payload as FoldPayload:null;
const unique=<T>(rows:T[]):T[]=>[...new Map(rows.map(row=>[JSON.stringify(row),row])).values()];
/** Logical topology is retained in each digest, never as dangling live edges. */
const topology=(graph:ExplorationGraph):{edges:ExpEdge[];anchors:Anchor[]}=>{
  const nodes=graph["nodes"];
  const digests=[...nodes.values()].map(payload).filter((p):p is FoldPayload=>!!p);
  const digestIds=new Set([...nodes.values()].filter(n=>payload(n)).map(n=>n.id));
  return {edges:unique([...graph["edges"].filter(e=>!digestIds.has(e.from)&&!digestIds.has(e.to)),...digests.flatMap(p=>p.originalEdges)]),
    anchors:unique([...graph["anchors"].filter(a=>!digestIds.has(a.nodeId)),...digests.flatMap(p=>p.originalAnchors)])};
};
const project=(graph:ExplorationGraph,edges:ExpEdge[],anchors:Anchor[]):void=>{
  const nodes=graph["nodes"], owners=new Map<string,string>();
  for(const n of nodes.values())for(const id of payload(n)?.members??[])owners.set(id,n.id);
  const live=(id:string):string|undefined=>nodes.has(id)?id:owners.get(id);
  graph["edges"]=unique(edges.flatMap(e=>{const from=live(e.from),to=live(e.to);return from&&to&&from!==to?[{from,rel:e.rel,to}]:[];}));
  graph["anchors"]=unique(anchors.flatMap(a=>{const nodeId=live(a.nodeId);return nodeId?[{nodeId,assetKey:a.assetKey}]:[];}));
};
export const touchLive=(graph:ExplorationGraph,stamps:Map<string,NodeStamp>,round:number):void=>{
  const nodes=graph["nodes"];
  for(const id of stamps.keys())if(!nodes.has(id))stamps.delete(id);
  for(const n of nodes.values()){
    if(payload(n))continue;
    const contentHash=hash(n),old=stamps.get(n.id);
    if(!old)stamps.set(n.id,{id:n.id,lastTouched:round,version:n.version??0,contentHash,touchVersion:n.touchVersion??0});
    else if(old.contentHash!==contentHash || old.version!==(n.version??0) || old.touchVersion!==(n.touchVersion??0)){
      old.lastTouched=round;old.version=n.version??0;old.contentHash=contentHash;old.touchVersion=n.touchVersion??0;
    }
  }
};
export const compactGraph=(graph:ExplorationGraph,stamps:Map<string,NodeStamp>,round:number,params:ColdParams=DEFAULT_COLD_PARAMS):Folded=>{
  if(!Number.isSafeInteger(params.coldAfterRounds)||params.coldAfterRounds<1||!Number.isSafeInteger(params.maxDigestSize)||params.maxDigestSize<1)throw new Error("invalid cold graph parameters");
  const nodes=graph["nodes"],edges=graph["edges"];
  // Direct payload edits and explicit visits both warm the node.
  touchLive(graph,stamps,round);
  const cold=new Set([...stamps.values()].filter(st=>{const n=nodes.get(st.id);return n && !payload(n) && n.kind!=="goal"&&n.kind!=="finding" && round-st.lastTouched>=params.coldAfterRounds;}).map(st=>st.id));
  const rescued:string[]=[];
  for(const id of [...cold]){
    const parents=edges.filter(e=>e.to===id&&(e.rel==="spawns"||e.rel==="derived_from")).map(e=>e.from);
    if(parents.some(parent=>{const kids=edges.filter(e=>e.from===parent&&(e.rel==="spawns"||e.rel==="derived_from")).map(e=>e.to);return kids.filter(k=>cold.has(k)).length===1&&kids.some(k=>!cold.has(k));})){
      cold.delete(id);rescued.push(id);
    }
  }
  const original=topology(graph),digests:string[]=[],folded:string[]=[];
  for(const group of coldGroups(cold,edges))for(let start=0;start<group.length;start+=params.maxDigestSize){
    const members=group.slice(start,start+params.maxDigestSize),set=new Set(members),memberNodes=members.map(id=>structuredClone(nodes.get(id)!));
    const originalEdges=original.edges.filter(e=>set.has(e.from)||set.has(e.to)),originalAnchors=original.anchors.filter(a=>set.has(a.nodeId));
    const digest=digestHash(memberNodes,originalEdges,originalAnchors),id=`digest-${digest}`;
    const data:FoldPayload={kind:"digest",members,memberNodes,originalEdges,originalAnchors,hash:digest,round};
    nodes.set(id,{id,kind:"hint",summary:`digest(${members.length}): ${memberNodes[0]!.summary.slice(0,60)}`,state:"pending",ts:new Date().toISOString(),payload:data});
    for(const member of members){nodes.delete(member);stamps.delete(member);folded.push(member);}digests.push(id);
  }
  project(graph,original.edges,original.anchors);
  return {digests,folded,rescued};
};
export const expandDigest=(graph:ExplorationGraph,digestId:string,stamps:Map<string,NodeStamp>,round:number):{expanded:string[]}=>{
  const nodes=graph["nodes"],node=nodes.get(digestId),data=node?payload(node):null;
  if(!data)return {expanded:[]};
  if(!Array.isArray(data.memberNodes)||!Array.isArray(data.originalEdges)||!Array.isArray(data.originalAnchors)||
    digestHash(data.memberNodes,data.originalEdges,data.originalAnchors)!==data.hash||digestId!==`digest-${data.hash}`||
    JSON.stringify(data.memberNodes.map(n=>n.id))!==JSON.stringify(data.members))throw Object.assign(new Error("cold digest integrity mismatch"),{code:"evidence_integrity"});
  if(data.members.some(id=>nodes.has(id)))throw Object.assign(new Error("expanded member ID conflict"),{code:"version_conflict"});
  const original=topology(graph);
  for(const member of data.memberNodes){nodes.set(member.id,structuredClone(member));stamps.set(member.id,{id:member.id,lastTouched:round,version:member.version??0,contentHash:hash(member),touchVersion:member.touchVersion??0});}
  nodes.delete(digestId);stamps.delete(digestId);project(graph,original.edges,original.anchors);
  return {expanded:[...data.members]};
};
interface PersistedStamps {version?:number;round:number;stamps:NodeStamp[]}
const versions=new WeakMap<Map<string,NodeStamp>,number>();
const readStamps=(root:string):Promise<PersistedStamps>=>readJson(root,"cold_stamps.json",()=>({version:0,round:0,stamps:[]}),value=>{
  const s=value as PersistedStamps;return !!s&&Number.isSafeInteger(s.round)&&s.round>=0&&Array.isArray(s.stamps)&&s.stamps.every(x=>typeof x.id==="string"&&Number.isSafeInteger(x.lastTouched)&&x.lastTouched>=0&&Number.isSafeInteger(x.version)&&x.version>=0);
});
export const loadStamps=async(root:string):Promise<{stamps:Map<string,NodeStamp>;round:number}>=>{
  const data=await readStamps(root),stamps=new Map(data.stamps.map(s=>[s.id,s]));versions.set(stamps,data.version??0);return {stamps,round:data.round};
};
export const saveStamps=async(root:string,stamps:Map<string,NodeStamp>,round:number):Promise<void>=>withRootLock(root,async()=>{
  const disk=await readStamps(root),expected=versions.get(stamps)??0;
  if((disk.version??0)!==expected)throw Object.assign(new Error("cold stamps version conflict"),{code:"version_conflict"});
  await writeJson(root,"cold_stamps.json",{version:expected+1,round,stamps:[...stamps.values()]});versions.set(stamps,expected+1);
});
