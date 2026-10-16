import { describe, expect, it } from "vitest";
import vm from "node:vm";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { deobfuscateCorpus } from "../src/domain/deobf.js";
import { parse } from "acorn";
import { scanDomSinks } from "../src/domain/domSinks.js";
import { analyzeGates } from "../src/domain/gates.js";
import { buildPermTree, flatCodes, parseUserRouteAuth } from "../src/domain/permTree.js";
import { renameIdentifiers } from "../src/domain/rename.js";
import { buildWebpackGraph } from "../src/domain/webpackGraph.js";

const run = (code: string) => vm.runInNewContext(code);
const corpus = async (source: string) => {
  const root=await mkdtemp(join(process.env.TMPDIR ?? "/root/.hermes/cache/scratch", "velric-js-"));
  const jsDir=join(root,"js");await mkdir(jsDir);await writeFile(join(jsDir,"app.js"),source);
  return {root,jsDir,source};
};
const deobf = async (source: string) => {
  const c=await corpus(source);
  const result=await deobfuscateCorpus({jsDir:c.jsDir,outputRoot:c.root});
  const code=result.restored.length ? await readFile(join(c.root,"js-deobf","app.js"),"utf8") : source;
  parse(code,{ecmaVersion:"latest"});
  return {code,result};
};
describe("D05 static candidates retain provenance", () => {
  it("finds RHS DOM sources without calling text proximity a proven chain", async () => {
    const c=await corpus('function a(){return location.hash}function b(){el.innerHTML="safe"}function c(){el.innerHTML=location.search}');
    const r=await scanDomSinks({jsDir:c.jsDir,outputRoot:c.root});
    const rhs=r.chains.find(c=>c.source==="location.search");
    expect(rhs).toBeDefined();
    expect(rhs).toMatchObject({confidence:"candidate",evidence:{kind:"direct-expression"}});
    expect(r.chains.some(c=>c.source==="location.hash")).toBe(false);
  });
  it("does not turn failure codes and session storage hints into executable gate patches", async () => {
    const c=await corpus('sessionStorage.getItem("auth");if(response.code===401){router.push("/login")}');
    const r=await analyzeGates({jsDir:c.jsDir,outputRoot:c.root});
    expect(r.suggestedConfig.localStorage).toEqual({});
    expect(r.suggestedConfig.neutralize.fields).toEqual([]);
    expect(r.storageCandidates[0]).toMatchObject({medium:"sessionStorage",key:"auth",confidence:"candidate"});
    expect(r.evidence.some(e=>e.excerpt.includes("401") && e.file==="app.js")).toBe(true);
  });
  it("bounds auth objects, resolves preceding aliases and preserves orphan/cycle entries", () => {
    const text='const x=o.HOME;const userRouteAuth={HOME:{url:x,control:["read"]}};const unrelated={BAD:{url:"/bad"}};';
    const entries=parseUserRouteAuth(text,{HOME:{name:"Home",link:"/home"}});
    expect(Object.keys(entries)).toEqual(["HOME"]);
    expect(entries.HOME).toMatchObject({url:"/home",control:["read"],confidence:"candidate"});
    expect(entries.HOME!.evidence).toBeDefined();
    const tree=buildPermTree({HOME:entries.HOME!,A:{code:"A",url:"/a",control:[]},B:{code:"B",url:"/b",control:[]},LOST:{code:"LOST",url:"/lost",control:[]}},{roots:["HOME"],prefixParent:{},extraParent:{A:"B",B:"A",LOST:"MISSING"}});
    expect(new Set(flatCodes(tree))).toEqual(new Set(["HOME","A","B","LOST"]));
    expect(tree.every(n=>n.confidence==="candidate" && n.basis)).toBe(true);
  });
});
describe("D03 conservative AST deobfuscation", () => {
  it("never rewrites mutable arrays, shadowed bindings, decoder effects or string-embedded code", async () => {
    for (const source of [
      '(()=>{const a=["a","b","c","d","e","f"];a[0]="changed";return a[0]})()',
      '(()=>{const a=["a","b","c","d","e","f"];function f(a){return a[0]}return f(["other"])})()',
      '(()=>{const a=["a","b","c","d","e","f"];let n=0;function d(i){n++;return a[i-1]}return [d(1),n]})()',
      '(()=>{const a=["a","b","c","d","e","f"];return "a[0]"})()',
    ]) {
      const {code}=await deobf(source);expect(run(code)).toEqual(run(source));
    }
  });
  it("restores immutable direct reads and pure decoder calls while preserving escaped literals", async () => {
    const source='(()=>{const a=["/api/a","quote\\\"x","c","d","e","f"];function d(i){return a[i-1]}return [a[0],d(2)]})()';
    const {code,result}=await deobf(source);
    expect(run(code)).toEqual(run(source));
    expect(result.restored[0]!.stringsRestored).toBe(2);
    expect(code).toContain('return ["/api/a",');
  });
  it("reconstructs dispatcher order and does not alter unrelated switches", async () => {
    const source='(()=>{const order=["2","0","1"];let i=0;let out="";while(true){switch(order[i++]){case "0":out+="A";continue;case "1":out+="B";continue;case "2":out+="C";continue;}break;}switch(out){case "CAB":out+="!";break;}return out})()';
    const {code,result}=await deobf(source);
    expect(run(code)).toBe("CAB!");
    expect(result.restored[0]!.switchSimplified).toBe(true);
    expect(code).toContain('case "CAB"');
  });
});
describe("D04 runtime-bound webpack graph", () => {
  it("does not treat ordinary objects, comments or strings as a runtime", () => {
    const g=buildWebpackGraph({source:'const ordinary={a(){},b(){}}; // __webpack_require__(1)\nconst fake="__webpack_require__.s=2";',sourceName:"plain.js"});
    expect(g.modules).toEqual([]);
    expect(g.entryIds).toEqual([]);
  });
  it("keeps sparse ids and resolves minified call expressions and the actual bootstrap entry", () => {
    const source='(function(t){function r(i){const m={exports:{}};t[i].call(m.exports,m,m.exports,r);return m.exports}return r(r.s=2)})([,function(m,e,r){r(99)},function(m,e,r){const s="r(98)";/* r(97) */r(1);function f(r){r(96)}},,function(m,e,r){}]);';
    const g=buildWebpackGraph({source,sourceName:"bundle.js"});
    expect(g.modules.map(m=>m.id)).toEqual(["1","2","4"]);
    expect(g.entryIds).toEqual(["2"]);
    expect(g.edges).toEqual([{from:"1",to:"99"},{from:"2",to:"1"}]);
    expect(g.modules[0]!.missing).toEqual(["99"]);
  });
});
describe("D01/D02 binding-safe rename", () => {
  it("preserves shorthand, destructuring defaults and class self binding", () => {
    const source = '(()=>{const a=7;const {b:a2=3}={};class C{static make(){return new C()}}return [Object.keys({a})[0],({a}).a,a2,C.make() instanceof C]})()';
    const result = renameIdentifiers(source);
    expect(run(result.code)).toEqual(run(source));
    expect(result.renamed).toBeGreaterThan(0);
    expect(renameIdentifiers(source)).toEqual(result);
  });
  it("expands destructuring shorthand without changing keys and keeps observable names", () => {
    for (const source of [
      '(()=>{const {a=9}={a:7};return [a,Object.keys({a}),({a}).a]})()',
      '(()=>{let a;({a}={a:7});return a})()',
      '(()=>{const a=()=>1;class C{};function f(){};return [a.name,C.name,f.name]})()',
    ]) {
      const result=renameIdentifiers(source);
      expect(run(result.code)).toEqual(run(source));
    }
  });
  it("preserves classic globals and dynamic eval/with visible names", () => {
    for(const source of ['var a=7;globalThis.a', '(()=>{const a=7;return eval("a")})()', 'var a=7;with({}){a}']) {
      expect(run(renameIdentifiers(source).code)).toEqual(run(source));
    }
  });
  it("keeps imported/exported public names and unique sibling maps", () => {
    const source='import {a} from "dep";export {a};export const b=1;function f(a){return a}function g(a){return a}';
    const r=renameIdentifiers(source);
    expect(r.code).toMatch(/import\s*\{a\s+as\s+/);
    expect(r.code).toMatch(/export\s*\{[^}]+\s+as\s+a\}/);
    expect(r.code).toContain('export const b=1');
    expect(Object.keys(r.map).filter(k=>k.endsWith(':a')).length).toBe(3);
  });
});
