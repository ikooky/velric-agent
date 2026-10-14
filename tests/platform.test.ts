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
