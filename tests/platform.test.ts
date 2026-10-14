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
