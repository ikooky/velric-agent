import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";

let server: http.Server;
let server2: http.Server;
const mkServer = (handlers: Record<string, (req: http.IncomingMessage, res: http.ServerResponse, q: URL) => void>, port: number): Promise<http.Server> => new Promise(resolve => {
  const s = http.createServer((req, res) => {
    const q = new URL(req.url ?? "/", "http://x");
    const keys = Object.keys(handlers);
    const exact = keys.find(k => k === `${req.method ?? "GET"} ${q.pathname}` || k === `* ${q.pathname}`);
    const prefix = keys.find(k => (k.endsWith("*") || k.includes("* ")) && !k.endsWith(" *") && new RegExp("^" + k.replace(/[*]/g, ".*") + "$").test(`${req.method ?? "GET"} ${q.pathname}`));
    const anyM = keys.find(k => k === `${req.method ?? "GET"} *` || k === "*");
    const h = handlers[exact ?? prefix ?? anyM ?? ""];
    if (h) h(req, res, q); else { res.writeHead(404).end("nf"); }
  });
  s.listen(port, "127.0.0.1", () => resolve(s));
});

beforeAll(async () => {
  server = await mkServer({
    "GET /redir": (req, res, q) => {
      const next = q.searchParams.get("next") ?? "";
      if (/[\r\n]/.test(next)) { res.writeHead(400).end("bad header chars"); return; }
      if (next.includes("redirect-probe.example")) { res.writeHead(302, { location: next }); res.end(); } else { res.writeHead(200).end("ok"); }
    },
    "GET /hpp": (req, res, q) => {
      const all = [...q.searchParams.entries()].filter(([k]) => k === "id");
      const val = all.length > 1 ? all[all.length - 1]![1]! : (q.searchParams.get("id") ?? "none");
      res.writeHead(200).end(`id=${val}`);
    },
    "GET /api/me*": (req, res) => { res.writeHead(200, { "cache-control": "public, max-age=3600" }).end('{"user":"alice","email":"alice@corp.example"}'); },
    "POST /proto": (req, res) => {
      let b = ""; req.on("data", c => b += c); req.on("end", () => {
        try { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ base: 1, ...JSON.parse(b) })); } catch { res.writeHead(400).end(); }
      });
    },
    "POST /register": (req, res) => {
      let b = ""; req.on("data", c => b += c); req.on("end", () => {
        try { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true, account: JSON.parse(b) })); } catch { res.writeHead(400).end(); }
      });
    },
  }, 18301);
  server2 = await mkServer({
    "POST *": (req, res) => {
      let b = ""; req.on("data", c => b += c); req.on("end", () => {
        const o = JSON.parse(b || "{}") as Record<string, unknown>;
        if (o["role"] === "admin" || o["isAdmin"] === true) res.writeHead(200).end('{"ok":true,"dashboard":"/admin"}');
        else res.writeHead(200).end('{"ok":true,"dashboard":"/home"}');
      });
    },
  }, 18302);
});
afterAll(async () => { await new Promise<void>(r => server.close(() => r())); await new Promise<void>(r => server2.close(() => r())); });

describe("attack-surface probes", () => {
  it("redirect-traverse: flags external redirect", async () => {
    const { probeRedirectTraversal } = await import("../src/domain/redirectTraverse.js");
    const dir = await mkdtemp(join(tmpdir(), "rt-"));
    const r = await probeRedirectTraversal({ baseUrl: "http://127.0.0.1:18301/redir?next=home", params: ["next"], outputRoot: join(dir, "o") });
    expect(r.redirectFindings.length).toBeGreaterThan(0);
    expect(r.redirectFindings.every(f => f.verdict === "redirects-external")).toBe(true);
  });
  it("hpp: detects last-wins parser", async () => {
    const { probeHpp } = await import("../src/domain/hppProbe.js");
    const dir = await mkdtemp(join(tmpdir(), "hpp-"));
    const r = await probeHpp({ baseUrl: "http://127.0.0.1:18301/hpp?id=1", params: ["id"], expectedValue: "1", outputRoot: join(dir, "o") });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.findings.some(f => f.evidence.reflected)).toBe(true);
  });
  it("proto-pollute: flags reflected merge gadget", async () => {
    const { probePrototype } = await import("../src/domain/protoPollute.js");
    const dir = await mkdtemp(join(tmpdir(), "pp-"));
    const r = await probePrototype({ url: "http://127.0.0.1:18301/proto", outputRoot: join(dir, "o") });
    expect(r.findings.length).toBeGreaterThan(0);
  });
  it("cache-deceive: flags suffix trick on cacheable private content", async () => {
    const { probeCache } = await import("../src/domain/cacheDeceive.js");
    const dir = await mkdtemp(join(tmpdir(), "cd-"));
    const r = await probeCache({ baseUrl: "http://127.0.0.1:18301", privatePath: "/api/me", outputRoot: join(dir, "o") });
    expect(r.deceptionSuspects.length).toBeGreaterThan(0);
  });
  it("role-escalate: no findings on echo-type API, findings on real semantics", async () => {
    const { probeRoleEscalation } = await import("../src/domain/roleEscalate.js");
    const dir = await mkdtemp(join(tmpdir(), "re-"));
    const echo = await probeRoleEscalation({ url: "http://127.0.0.1:18301/register", bodyTemplate: '{"username":"bob"}', outputRoot: join(dir, "o1"), fields: ["role", "isAdmin"] });
    expect(echo.findings.length).toBe(0);
    const real = await probeRoleEscalation({ url: "http://127.0.0.1:18302/", bodyTemplate: '{"username":"bob"}', outputRoot: join(dir, "o2"), fields: ["role", "isAdmin"] });
    expect(real.findings.length).toBeGreaterThan(0);
    expect(real.findings.some(f => f.field === "role" && f.value === "admin")).toBe(true);
  });
  it("hpp: non-echo param produces no finding", async () => {
    const { probeHpp } = await import("../src/domain/hppProbe.js");
    const dir = await mkdtemp(join(tmpdir(), "hpp2-"));
    const r = await probeHpp({ baseUrl: "http://127.0.0.1:18301/redir?next=home", params: ["next"], outputRoot: join(dir, "o") });
    expect(r.findings.length).toBe(0);
  });
});
