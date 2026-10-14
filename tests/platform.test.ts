import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";

describe("trafficRecorder", () => {
  it("records each CONNECT tunnel exactly once with truthful status", async () => {
    const { TrafficRecorder } = await import("../src/domain/trafficRecorder.js");
    const dir = await mkdtemp(join(tmpdir(), "velric-rec-"));
    const rec = new TrafficRecorder({ outputRoot: dir });
    const port = await rec.start(0);
    // dead upstream: CONNECT must record a non-200/errored tunnel once
    await new Promise<void>((resolve) => {
      const sock = connect(port, "127.0.0.1", () => {
        sock.write("CONNECT 127.0.0.1:1:443 HTTP/1.1\r\nHost: x\r\n\r\n");
      });
      sock.on("data", () => { sock.destroy(); resolve(); });
      sock.on("error", () => resolve());
      setTimeout(() => { sock.destroy(); resolve(); }, 4000);
    });
    await new Promise((r) => setTimeout(r, 300));
    const ex = rec.getExchanges();
    expect(ex.length).toBe(1);
    expect(ex[0]!.via).toBe("https-tunnel");
    expect(ex[0]!.status).not.toBe(200); // failed tunnel is not logged as success
    await rec.stop();
    const nd = await readFile(join(dir, "traffic.ndjson"), "utf8");
    expect(nd.trim().split("\n").length).toBe(1);
  });
});

describe("siteMap params shape", () => {
  it("accepts paramMerge top-level array and legacy wrapper", async () => {
    const { buildSiteMap } = await import("../src/domain/siteMap.js");
    const dir = await mkdtemp(join(tmpdir(), "velric-sm-"));
    await writeFile(join(dir, "params_merged.json"), JSON.stringify([
      { method: "GET", path: "/api/x", fields: [{ name: "page", in: "query", confidence: "high" }] },
    ]));
    await writeFile(join(dir, "api_merged.txt"), "/api/x\n");
    const m = await buildSiteMap({ baseUrl: "https://t.example/", outputRoot: dir });
    expect(m.params.length).toBe(1);
    expect(m.params[0]!.fields).toEqual(["page"]);
    expect(m.apis).toEqual(["/api/x"]);
  });
});

describe("gates operator parsing", () => {
  it("captures === values that the old split dropped", async () => {
    const { analyzeGates } = await import("../src/domain/gates.js");
    const dir = await mkdtemp(join(tmpdir(), "velric-gates-"));
    const jsDir = join(dir, "js");
    await mkdir(jsDir, { recursive: true });
    await writeFile(join(jsDir, "app.js"), 'if(r.code===0){a()}else if(r.ret!==1){b()}var x=r.status==200;');
    const g = await analyzeGates({ jsDir, outputRoot: dir });
    expect(g.interceptorGate.successValues).toContain("0");
    expect(g.interceptorGate.successValues).toContain("200");
  });
});

describe("trafficRecorder MITM", () => {
  it("decrypts HTTPS via in-process CA and records the exchange", async () => {
    const { TrafficRecorder, searchTraffic } = await import("../src/domain/trafficRecorder.js");
    const { createOrLoadCA } = await import("../src/domain/mitm.js");
    const forge = (await import("node-forge")).default;
    const tls = await import("node:tls");
    const { connect } = await import("node:net");
    const { readFileSync } = await import("node:fs");
    const dir = await mkdtemp(join(tmpdir(), "velric-mitm-"));

    // self-signed HTTPS target
    const tKeys = forge.pki.rsa.generateKeyPair(2048);
    const tCert = forge.pki.createCertificate();
    tCert.publicKey = tKeys.publicKey;
    tCert.serialNumber = "77";
    tCert.validity.notBefore = new Date();
    tCert.validity.notAfter = new Date(Date.now() + 86400000);
    tCert.setSubject([{ name: "commonName", value: "127.0.0.1" }]);
    tCert.setIssuer([{ name: "commonName", value: "127.0.0.1" }]);
    tCert.setExtensions([{ name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] }]);
    tCert.sign(tKeys.privateKey, forge.md.sha256.create());
    const tlsServer = tls.createServer({ key: forge.pki.privateKeyToPem(tKeys.privateKey), cert: forge.pki.certificateToPem(tCert) }, (sock) => {
      let buf = "";
      sock.on("data", (d) => {
        buf += d.toString();
        if (buf.includes("\r\n\r\n")) {
          sock.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 19\r\nConnection: close\r\n\r\nsecret-https-body-x");
          sock.end();
        }
      });
    });
    await new Promise<void>((r) => tlsServer.listen(18993, "127.0.0.1", r));

    const rec = new TrafficRecorder({ outputRoot: dir, mitm: true });
    const port = await rec.start(0);

    const result = await new Promise<{ clientGot: string }>((resolve, reject) => {
      const sock = connect(port, "127.0.0.1", () => {
        sock.write("CONNECT 127.0.0.1:18993 HTTP/1.1\r\nHost: 127.0.0.1:18993\r\n\r\n");
      });
      let hs = "";
      let clientTls: import("node:tls").TLSSocket | null = null;
      const timer = setTimeout(() => reject(new Error("timeout")), 15000);
      sock.on("data", (d) => {
        if (clientTls) return;
        hs += d.toString();
        if (hs.includes("200")) {
          const caPem = readFileSync(join(dir, "mitm-ca.cert.pem"), "utf8");
          clientTls = tls.connect({ socket: sock, rejectUnauthorized: false }, () => {
            clientTls!.write("GET /mitm-test HTTP/1.1\r\nHost: 127.0.0.1:18993\r\nConnection: close\r\n\r\n");
          });
          clientTls.on("data", (dd) => { clearTimeout(timer); resolve({ clientGot: dd.toString().split("\r\n\r\n").pop() ?? "" }); });
          clientTls.on("error", (e) => { clearTimeout(timer); reject(e); });
        }
      });
      sock.on("error", (e) => { clearTimeout(timer); reject(e); });
    });
    expect(result.clientGot).toContain("secret-https-body-x");

    await new Promise((r) => setTimeout(r, 800));
    const q = await searchTraffic({ outputRoot: dir, text: "mitm-test" });
    expect(q.total).toBeGreaterThanOrEqual(1);
    const https = q.exchanges.find((e) => e.url.startsWith("https://"));
    expect(https, "decrypted exchange recorded").toBeTruthy();
    expect(https!.status).toBe(200);
    expect(https!.respBodyBytes).toBe(19);
    await rec.stop();
    tlsServer.close();
  });
});

describe("scanPlatform", () => {
  it("runs a project->task->pipeline and stores assets with task provenance", async () => {
    const { createProject, createTask, runTask, listAssets, countAssets } = await import("../src/domain/scanPlatform.js");
    const { createServer } = await import("node:http");
    const dir = await mkdtemp(join(tmpdir(), "velric-sp-"));

    const srv = createServer((req, res) => {
      if (req.url === "/admin/") { res.writeHead(200, { "content-type": "text/html" }); res.end("<html><head><title>Admin Console</title></head><body>dashboard</body></html>"); return; }
      res.writeHead(404); res.end("nope");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    const target = `http://127.0.0.1:${port}`;

    const p = await createProject(dir, { name: "t", targets: [target] });
    const t = await createTask(dir, { projectId: p.id, name: "webmap", modules: ["fingerprint", "dir_scan"] });
    const r = await runTask(dir, { taskId: t.id, timeoutMs: 10000 });
    expect(r.status).toBe("done");
    expect(r.stageLog.length).toBe(2);
    const eps = await listAssets(dir, { type: "endpoint" });
    expect(eps.total).toBeGreaterThanOrEqual(1);
    expect(eps.items.some((a) => a.value.startsWith("/admin/"))).toBe(true);
    const cnt = await countAssets(dir, { taskTag: `task:${t.id}` });
    expect(cnt.total).toBeGreaterThanOrEqual(1);
    // provenance: every task-tagged asset carries the tag
    for (const a of eps.items) expect(a.taskTag).toBe(`task:${t.id}`);
    // unknown module rejected
    await expect(createTask(dir, { projectId: p.id, name: "bad", modules: ["nope"] })).rejects.toThrow(/unknown modules/);
    srv.close();
  });

  it("chains phase2 from phase1 subdomain assets via sourceTask", async () => {
    const { createProject, createTask, runTask } = await import("../src/domain/scanPlatform.js");
    const { AssetStore } = await import("../src/domain/graphs.js");
    const dir = await mkdtemp(join(tmpdir(), "velric-sp-"));

    const p = await createProject(dir, { name: "chain", targets: ["http://example.org"] });
    const t1 = await createTask(dir, { projectId: p.id, name: "p1", modules: ["fingerprint"], targets: ["http://example.org"] });
    // task without sourceTask and without targets falls back to project targets — ok.
    const r1 = await runTask(dir, { taskId: t1.id, timeoutMs: 4000 });
    // inject a subdomain tagged with task:t1 (simulating subdomain_scan output)
    const store = new AssetStore(dir);
    await store.load();
    store.upsert({ type: "subdomain", value: "sub.example.org", taskTag: `task:${t1.id}` });
    await store.save();
    const t2 = await createTask(dir, { projectId: p.id, name: "p2", modules: ["fingerprint"], sourceTask: t1.id });
    // runTask resolves targets from phase1's subdomain assets; network will
    // fail against a fake host but the resolution itself must engage (stage
    // detail shows the resolved target, not _resolve:fail).
    const r2 = await runTask(dir, { taskId: t2.id, timeoutMs: 4000 });
    expect(r2.stageLog[0]!.detail).toContain("sub.example.org");
    // sourceTask must be done: fresh task chained to a pending task is rejected at create
    const t3 = await createTask(dir, { projectId: p.id, name: "p3", modules: ["fingerprint"], targets: ["http://example.org"] });
    const t4 = await createTask(dir, { projectId: p.id, name: "p4", modules: ["fingerprint"], sourceTask: t3.id });
    await expect(runTask(dir, { taskId: t4.id, timeoutMs: 4000 })).rejects.toThrow(/must be done/);
  });
});
