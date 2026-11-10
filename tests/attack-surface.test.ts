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

import { probeValueAbuse } from "../src/domain/valueAbuse.js";

describe("value-abuse probe", () => {
  it("confirms persisted negative quantity with read-back verification", async () => {
    const state: Record<string, unknown>[] = [];
    const srv = http.createServer((req, res) => {
      if (req.method === "POST" && req.url === "/api/items") {
        let b = ""; req.on("data", c => b += c); req.on("end", () => {
          const o = JSON.parse(b) as Record<string, unknown>;
          state.push(o);
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(o));
        });
        return;
      }
      if (req.method === "GET" && req.url === "/api/items") { res.writeHead(200).end(JSON.stringify(state)); return; }
      res.writeHead(404).end();
    });
    await new Promise<void>(r => srv.listen(18305, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "va-"));
      const r = await probeValueAbuse({ url: "http://127.0.0.1:18305/api/items", bodyTemplate: '{"BasketId":1,"ProductId":1,"quantity":1}', fields: ["quantity"], verifyUrl: "http://127.0.0.1:18305/api/items", outputRoot: join(dir, "o") });
      expect(r.confirmed.length).toBeGreaterThan(0);
      expect(r.confirmed.some(c => c.kind === "negative")).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
});

import { probeSqli } from "../src/domain/sqliProbe.js";

describe("sqli-probe", () => {
  it("confirms boolean-blind divergence on vulnerable mock", { timeout: 30000 }, async () => {
    const srv = http.createServer((req, res) => {
      const q = new URL(req.url ?? "/", "http://x");
      const v = q.searchParams.get("id") ?? "";
      // 模拟可注入: ' AND '1'='1 返回数据, ' AND '1'='2 返回空
      if (/AND '1'='1/.test(v)) { res.writeHead(200).end('[{"row":1}]'); return; }
      if (/AND '1'='2/.test(v)) { res.writeHead(200).end('[]'); return; }
      if (v.includes("'")) { res.writeHead(500).end('{"error":"SQLITE_ERROR: near ...: syntax error"}'); return; }
      res.writeHead(200).end('[{"row":1}]');
    });
    await new Promise<void>(r => srv.listen(18306, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "sq-"));
      const r = await probeSqli({ url: "http://127.0.0.1:18306/api/x?id=1", param: "id", outputRoot: join(dir, "o") });
      expect(r.leads.length).toBeGreaterThan(0); // error-oracle 命中
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
  it("auth-bypass mode flags login returning token", { timeout: 30000 }, async () => {
    const srv = http.createServer((req, res) => {
      let b = ""; req.on("data", c => b += c); req.on("end", () => {
        let o: Record<string, string>;
        try { o = JSON.parse(b || "{}") as Record<string, string>; } catch { res.writeHead(400).end("bad"); return; }
        if (o["email"]?.includes(" or ")) { res.writeHead(200).end('{"authentication":{"token":"eyJhbGciOiJIUzI1NiJ9.x.y","bid":1,"umail":"admin@x.io"}}'); return; }
        res.writeHead(401).end('{"error":"Invalid credentials"}');
      });
    });
    await new Promise<void>(r => srv.listen(18307, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "sq2-"));
      const r = await probeSqli({ url: "http://127.0.0.1:18307/login", param: "email", in: "body", bodyTemplate: '{"email":"a@b.c","password":"x"}', authBypass: true, outputRoot: join(dir, "o") });
      expect(r.confirmed.length).toBeGreaterThan(0);
      expect(r.confirmed.some(c => c.technique === "auth-bypass")).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
});

import { probeNosqli } from "../src/domain/nosqliProbe.js";
import { probeCredBrute } from "../src/domain/credBrute.js";

describe("nosqli & cred-brute", () => {
  it("nosqli: $ne operator executed as query (multi-row divergence)", { timeout: 30000 }, async () => {
    const srv = http.createServer((req, res) => {
      let b = ""; req.on("data", c => b += c); req.on("end", () => {
        let o: Record<string, unknown>;
        try { o = JSON.parse(b || "{}"); } catch { res.writeHead(400).end("bad"); return; }
        const id = o["id"];
        if (id && typeof id === "object" && "$ne" in (id as object)) { res.writeHead(200).end('{"modified":7}'); return; }
        if (typeof id === "string" && id === "known") { res.writeHead(200).end('{"modified":1}'); return; }
        res.writeHead(404).end('{"modified":0}');
      });
    });
    await new Promise<void>(r => srv.listen(18308, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "no-"));
      const r = await probeNosqli({ url: "http://127.0.0.1:18308/x", param: "id", in: "body", method: "PATCH", bodyTemplate: '{"id":"known"}', outputRoot: join(dir, "o") });
      expect(r.confirmed.some(c => c.vector === "operator-$ne")).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
  it("cred-brute: classifies valid and invalid credentials", { timeout: 30000 }, async () => {
    const srv = http.createServer((req, res) => {
      let b = ""; req.on("data", c => b += c); req.on("end", () => {
        const o = JSON.parse(b || "{}") as Record<string, string>;
        if (o["user"] === "bob" && o["pass"] === "hunter2") { res.writeHead(200).end('{"token":"eyJ.x.y"}'); return; }
        res.writeHead(401).end('{"error":"bad credentials"}');
      });
    });
    await new Promise<void>(r => srv.listen(18309, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "cb-"));
      const r = await probeCredBrute({ url: "http://127.0.0.1:18309/login", bodyTemplate: '{"user":"{USER}","pass":"{PASS}"}', pairs: [{ user: "bob", pass: "wrong" }, { user: "bob", pass: "hunter2" }], outputRoot: join(dir, "o") });
      expect(r.valid.length).toBe(1);
      expect(r.valid[0]!.pass).toBe("hunter2");
      expect(r.semantics["bad-cred"]).toBe(1);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
});

import { probeRace } from "../src/domain/raceProbe.js";
import { probeSsti } from "../src/domain/sstiProbe.js";

describe("race-probe & ssti-probe", () => {
  it("race: detects all-admitted concurrent mutations", { timeout: 30000 }, async () => {
    let admitted = 0;
    const srv = http.createServer((req, res) => {
      // 模拟无锁: 全部接受
      admitted++;
      res.writeHead(200).end('{"ok":true}');
    });
    await new Promise<void>(r => srv.listen(18310, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "rc-"));
      const r = await probeRace({ url: "http://127.0.0.1:18310/redeem", method: "POST", body: '{"code":"X"}', concurrency: 5, rounds: 2, outputRoot: join(dir, "o") });
      expect(r.admitted).toBe(10);
      expect(r.raceSuspected).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
  it("ssti: flags evaluated canary (49) without literal echo", { timeout: 30000 }, async () => {
    const srv = http.createServer((req, res) => {
      const q = new URL(req.url ?? "/", "http://x");
      const v = q.searchParams.get("t") ?? "";
      if (v.includes("{{7*7}}")) { res.writeHead(200).end('rendered: 49'); return; }
      res.writeHead(200).end(`echo ${v}`);
    });
    await new Promise<void>(r => srv.listen(18311, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "ss-"));
      const r = await probeSsti({ url: "http://127.0.0.1:18311/render?t=x", param: "t", outputRoot: join(dir, "o") });
      expect(r.confirmed.some(c => c.payload === "{{7*7}}")).toBe(true);
      // echo型(字面回显)不confirmed:
      expect(r.confirmed.every(c => !c.literalEcho)).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
});

import { probeHostPoison } from "../src/domain/hostPoison.js";
import { probeUpload } from "../src/domain/uploadProbe.js";

describe("host-poison & upload-probe", () => {
  it("host-poison: detects canary in generated URL", { timeout: 30000 }, async () => {
    const srv = http.createServer((req, res) => {
      const host = req.headers["x-forwarded-host"] ?? req.headers.host ?? "";
      if (String(host).includes("evil")) { res.writeHead(200).end(`<a href="https://${String(host)}/reset?token=x">reset</a>`); return; }
      res.writeHead(200).end("normal page");
    });
    await new Promise<void>(r => srv.listen(18312, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "hp-"));
      const r = await probeHostPoison({ url: "http://127.0.0.1:18312/page", canaryHost: "canary.evil.example", outputRoot: join(dir, "o") });
      expect(r.poisoned.length).toBeGreaterThan(0);
      expect(r.poisoned.some(p => p.vector === "x-forwarded-host")).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
  it("upload-probe: flags exec-risk acceptance, rejects clean server", { timeout: 30000 }, async () => {
    let stored: string[] = [];
    const srv = http.createServer((req, res) => {
      let b = Buffer.alloc(0); req.on("data", c => b = Buffer.concat([b, c])); req.on("end", () => {
        const m = /filename="([^"]+)"/.exec(b.toString("latin1"));
        stored.push(m?.[1] ?? "?");
        if (m && (/\.(php|jsp|html|svg|shtml|js)\b/i.test(m[1]!) || m[1]!.startsWith(".ht"))) { res.writeHead(415).end('{"error":"only images"}'); return; }
        res.writeHead(204).end();
      });
    });
    await new Promise<void>(r => srv.listen(18313, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "up-"));
      const r = await probeUpload({ url: "http://127.0.0.1:18313/up", outputRoot: join(dir, "o") });
      expect(r.dangerous.length).toBe(0); // 干净服务器0危险
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
});

import { probeLdap } from "../src/domain/ldapProbe.js";
import { probeApiVersion } from "../src/domain/apiVersion.js";
import { probeResetAbuse } from "../src/domain/resetAbuse.js";

describe("ldap / api-version / reset-abuse", () => {
  it("ldap: wildcard widens filter (row divergence)", { timeout: 30000 }, async () => {
    const srv = http.createServer((req, res) => {
      const uid = new URL(req.url ?? "/", "http://x").searchParams.get("uid") ?? "";
      if (uid === "*") { res.writeHead(200).end('{"data":[1,2,3]}'); return; }
      if (uid.includes(")(")) { res.writeHead(400).end("Bad search filter"); return; }
      res.writeHead(200).end('{"data":[1]}');
    });
    await new Promise<void>(r => srv.listen(18322, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "ld-"));
      const r = await probeLdap({ url: "http://127.0.0.1:18322/dir?uid=alice", param: "uid", outputRoot: join(dir, "o") });
      expect(r.confirmed.some(c => c.vector === "wildcard")).toBe(true);
      expect(r.leads.some(l => l.vector === "filter-widen-and")).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
  it("api-version: flags anonymous data on sibling version", { timeout: 30000 }, async () => {
    const data = JSON.stringify({ data: [{ id: 1, secret: "s3cret-kpi-value" }] });
    const srv = http.createServer((req, res) => {
      const m = /^\/api\/(v\d+)\//.exec(req.url ?? "");
      if (!m) { res.writeHead(404).end(); return; }
      if (m[1] === "v2") { if (!req.headers.authorization) { res.writeHead(401).end(); return; } res.writeHead(200).end(data); return; }
      if (m[1] === "v1") { res.writeHead(200).end(data); return; }
      res.writeHead(404).end();
    });
    await new Promise<void>(r => srv.listen(18323, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "av-"));
      const r = await probeApiVersion({ url: "http://127.0.0.1:18323/api/v2/kpis", outputRoot: join(dir, "o") });
      expect(r.leaks.some(l => l.version === "api/v1")).toBe(true);
      expect(r.leaks.every(l => l.version !== "api/v2")).toBe(true);
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
  it("reset-abuse: full takeover proof chain", { timeout: 30000 }, async () => {
    const pass: Record<string, string> = {};
    const srv = http.createServer((req, res) => {
      const u = req.url ?? "";
      let b = ""; req.on("data", c => b += c); req.on("end", () => {
        const o = JSON.parse(b || "{}") as Record<string, string>;
        if (u === "/reset") {
          if (o["answer"] === "fluffy") { pass["v"] = o["new"] ?? ""; res.writeHead(200).end(JSON.stringify({ user: { email: o["email"], password: "deadbeefdeadbeefdeadbeefdeadbeef" } })); return; }
          res.writeHead(401).end("Wrong answer"); return;
        }
        if (u === "/login") {
          if (pass["v"] && o["password"] === pass["v"]) { res.writeHead(200).end('{"authentication":{"token":"x.y.z"}}'); return; }
          res.writeHead(401).end(); return;
        }
        res.writeHead(404).end();
      });
    });
    await new Promise<void>(r => srv.listen(18324, "127.0.0.1", () => r()));
    try {
      const dir = await mkdtemp(join(tmpdir(), "rs-"));
      const r = await probeResetAbuse({ resetUrl: "http://127.0.0.1:18324/reset", loginUrl: "http://127.0.0.1:18324/login", email: "victim@x.io", answers: ["rex", "bella", "fluffy"], newPass: "NewP@ss1", resetTemplate: '{"email":"{EMAIL}","answer":"{ANSWER}","new":"{NEWPASS}","repeat":"{NEWPASS}"}', loginTemplate: '{"email":"{EMAIL}","password":"{PASS}"}', outputRoot: join(dir, "o") });
      expect(r.takeover).toBe(true);
      expect(r.acceptedAnswers).toContain("fluffy");
      expect(r.hashEcho).toBe("deadbeefdeadbeefdeadbeefdeadbeef");
    } finally { await new Promise<void>(r => srv.close(() => r())); }
  });
});
