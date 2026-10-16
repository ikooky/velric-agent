import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile, symlink, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { withRootLock, readJson, writeJson, putBlob, readBlob, safePath } from "../src/core/storage.js";
import { roleRequest, SessionJar } from "../src/core/credentials.js";
import { withExecution, recordReceipt, executionRunId } from "../src/core/execution.js";
const root = () => mkdtemp(join(tmpdir(), "native-core-"));
describe("native storage transactions", () => {
  it("keeps every concurrent successful update", async () => {
    const r = await root();
    await Promise.all(Array.from({length: 12}, () => withRootLock(r, async () => {
      const value = await readJson(r, "counter.json", () => ({n:0}));
      await writeJson(r, "counter.json", {n:value.n+1});
    })));
    expect((await readJson(r,"counter.json",()=>({n:0}))).n).toBe(12);
  });
  it("allows nested transactions and keeps original corrupt bytes", async () => {
    const r = await root();
    await withRootLock(r, () => withRootLock(r, () => writeJson(r,"good.json",{ok:true})));
    await writeFile(join(r,"bad.json"),"{");
    await expect(readJson(r,"bad.json",()=>({}))).rejects.toMatchObject({code:"corrupt_state"});
    expect(await readFile(join(r,"bad.json"),"utf8")).toBe("{");
  });
  it("rejects tampered evidence and malformed hash paths", async () => {
    const r=await root(); const stored=await putBlob(r,Buffer.from("original"));
    expect((await readBlob(r,stored.hash))?.toString()).toBe("original");
    await writeFile(stored.path,"changed");
    await expect(readBlob(r,stored.hash)).rejects.toMatchObject({code:"evidence_integrity"});
    await expect(readBlob(r,"../outside")).rejects.toMatchObject({code:"invalid_hash"});
  });
  it("refuses symlink parents and file targets", async () => {
    const r=await root(), outside=await root();
    await symlink(outside,join(r,"link"));
    await expect(safePath(r,"link/x.txt")).rejects.toMatchObject({code:"path_escape"});
    await symlink(join(outside,"x.txt"),join(r,"file"));
    await expect(writeJson(r,"file",{bad:true})).rejects.toMatchObject({code:"path_escape"});
  });
});
describe("native credential contexts",()=>{
  it("applies explicit role headers last and removes all stale identity carriers",()=>{
    const result=roleRequest({url:"https://site.invalid/api",headers:{Cookie:"old=1",Authorization:"Bearer old","X-Auth-Token":"old","X-Tenant":"victim"},body:"{\"name\":\"unchanged\"}"},{credential:"Authorization: Bearer new",headers:{"x-tenant":"attacker"}});
    expect(result.headers).toEqual({authorization:"Bearer new","x-tenant":"attacker"});
    expect(result.body).toBe('{"name":"unchanged"}');
  });
  it("anonymous strips explicit query and body credential fields but keeps business ids",()=>{
    const result=roleRequest({url:"https://site.invalid/api?access_token=old&id=42",headers:{"x-api-key":"old"},body:'{"token":"old","owner":42}'},{anonymous:true});
    expect(new URL(result.url).searchParams.has("access_token")).toBe(false);
    expect(new URL(result.url).searchParams.get("id")).toBe("42");
    expect(result.headers).toEqual({}); expect(JSON.parse(String(result.body))).toEqual({owner:42});
  });
  it("rotates same-name cookies and does not leak credentials across origins or paths",()=>{
    const jar=new SessionJar();jar.update("https://site.invalid/login",["sid=one; Path=/; Secure; HttpOnly","scoped=x; Path=/admin"]);
    jar.update("https://site.invalid/login",["sid=two; Path=/; Secure"]);jar.setBearer("https://site.invalid","new");
    expect(jar.header("https://site.invalid/profile")).toBe("sid=two");
    expect(jar.headers("https://site.invalid/profile").authorization).toBe("Bearer new");
    expect(jar.headers("https://site.invalid.evil/profile")).toEqual({});
    expect(jar.header("http://site.invalid/profile")).toBe("");
    jar.update("https://site.invalid/login",["sid=; Max-Age=0; Path=/"]);
    expect(jar.header("https://site.invalid/profile")).toBe("");
  });
});
describe("native execution receipts",()=>{
  it("zero-request execution adds no observation and records each real receipt immutably",async()=>{
    const r=await root();
    await withExecution({tool:"local",ledgerRoot:r,runId:"run-test"},async()=>expect(executionRunId()).toBe("run-test"));
    expect(await readJson(r,"observation_ledger.json",()=>[])).toEqual([]);
    const receipt=await withExecution({tool:"http",ledgerRoot:r,runId:"run-test"},()=>recordReceipt({url:"https://site.invalid/api?id=42",method:"POST",status:200,requestHash:"a".repeat(64),responseHash:"b".repeat(64),principal:"user",complete:true}));
    const rows=await readJson<Array<{id:string;url:string;runId:string}>>(r,"observation_ledger.json",()=>[]);
    expect(rows).toHaveLength(1);expect(rows[0]?.id).toBe(receipt.id);expect(rows[0]?.url).toContain("?id=42");expect(rows[0]?.runId).toBe("run-test");
  });
});
