import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeVmCorpus, analyzeVmSource } from "../src/domain/vmAnalyze.js";

const vmSample = `!function(){var U=void 0,y=parseInt,E0=Function;var E=15,l=10,m=12,x=16,S=13,$=11;var C=[];C[9]=["pc","len","0","ok","getToken","sig","seed","string",113,667,"call",8];function DG(d,P){d[7]=x;while(d[7]!==U){var aE=d[7]&31;var O=d[7]>>5&31;switch(aE){case 0:d[4]=d[1]+d[2];d[7]=612;break;case 1:var r=[];r.push(d[4],d[5]);d[6]=E0(C[9][10],null,r.join(""));d[7]=425;break;case 2:if(d[4]<d[3]){d[7]=512}else{d[7]=425}break;case 3:d[0]=d[1][C[9][7]];d[7]=72;break;case 4:try{d[8]=d[5]in d[4];d[7]=88}catch(e){d[7]=96}break;case 5:var rx=new RegExp("\\\\s","g");d[6]=y(d[4].replace(rx,""));d[7]=104;break;case 6:return d[6];case 7:var arr=[];arr.push(69,d[4],445);d[9]=arr;break;case 8:document.cookie=C[9][4]+"="+d[6];d[7]=130;break;default:return U}}return U}var out=DG([1,2,3,0,0,0,0,15,0,0],null);window.__awsc={getToken:function(){return out}};}();`;

describe("vm-analyze", () => {
  it("identifies an opcode dispatcher VM and classifies opcodes", () => {
    const result = analyzeVmSource(vmSample, "risk-engine.min.js", 45);
    expect(result.isVm).toBe(true);
    expect(result.signals).toContain("bitfield-decode");
    expect(result.interpreters.length).toBeGreaterThan(0);
    const interp = result.interpreters[0];
    expect(interp.cases).toBe(10);
    expect(interp.opcodes.find(o => o.caseValue === "6")?.kind).toBe("RETURN");
    expect(interp.opcodes.find(o => o.caseValue === "8")?.kind).toBe("DOM");
    const branch = interp.opcodes.find(o => o.caseValue === "2");
    expect(branch?.kind).toBe("BRANCH");
    expect(branch?.branchTargets).toContain("512");
  });

  it("recovers the constant prelude mapping", () => {
    const result = analyzeVmSource(vmSample, "x.js", 45);
    const names = result.constantMaps.map(m => m.name);
    expect(names).toContain("E");
    expect(result.constantMaps.find(m => m.name === "E")?.value).toBe(15);
  });

  it("does not flag ordinary application code", () => {
    const normal = "const app=require('express');app.get('/u',function(r,s){var n=['a','b'];s.json(n)});app.listen(3000);";
    const result = analyzeVmSource(normal, "app.js", 45);
    expect(result.isVm).toBe(false);
  });

  it("corpus mode writes vm_analysis.json", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vmcorpus-"));
    const jsDir = join(dir, "js");
    await mkdir(jsDir);
    await writeFile(join(jsDir, "vm.js"), vmSample);
    await writeFile(join(jsDir, "app.js"), "console.log(1)");
    const out = await analyzeVmCorpus({ jsDir, outputRoot: join(dir, "out") });
    expect(out.scanned).toBe(2);
    expect(out.vmFiles.map(f => f.file)).toEqual(["vm.js"]);
    expect(out.artifacts.some(a => a.path.endsWith("vm_analysis.json"))).toBe(true);
  });
});
