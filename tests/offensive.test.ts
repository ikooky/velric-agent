import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp, writeFile, mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import net from "node:net";

/** Mocks for the backend-takeover / paywall-bypass command batch. */

const servers: (http.Server | net.Server)[] = [];
const track = <T extends http.Server | net.Server>(s: T): T => { servers.push(s); return s; };
afterAll(() => { for (const s of servers) s.close(); });

const mk = (handler: http.RequestListener, port: number): Promise<http.Server> => new Promise((resolve) => {
  const s = track(http.createServer(handler));
  s.listen(port, "127.0.0.1", () => resolve(s));
});
const body = async (req: http.IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString();
};

describe("admin default credentials", () => {
  it("detects a Tomcat manager and finds tomcat:tomcat", { timeout: 20000 }, async () => {
    await mk((req, res) => {
      const auth = req.headers.authorization;
      if (!auth) { res.writeHead(401, { "www-authenticate": 'Basic realm="Tomcat Manager Application"' }).end("auth"); return; }
      const ok = auth === `Basic ${Buffer.from("tomcat:tomcat").toString("base64")}`;
      if (!ok) { res.writeHead(401, { "www-authenticate": 'Basic realm="Tomcat Manager Application"' }).end("bad"); return; }
      res.writeHead(200, { "content-type": "text/html" }).end("<h1>Tomcat Web Application Manager</h1>");
    }, 18331);
    const { probeAdminCreds } = await import("../src/domain/adminCreds.js");
    const dir = await mkdtemp(join(tmpdir(), "ac-"));
    const r = await probeAdminCreds({ baseUrl: "http://127.0.0.1:18331", outputRoot: join(dir, "o"), panels: ["tomcat-manager"] });
    expect(r.detected.map((d) => d.panel)).toContain("tomcat-manager");
    expect(r.hits[0]).toMatchObject({ panel: "tomcat-manager", username: "tomcat", password: "tomcat" });
  });
});

describe("unauthenticated services", () => {
  it("flags an open Redis and an open Docker API", { timeout: 20000 }, async () => {
    const redis = track(net.createServer((sock) => {
      sock.on("data", () => sock.write("$100\r\n# Server\r\nredis_version:7.2.4\r\nconnected_clients:3\r\ndb0:keys=7,expires=0\r\n"));
    }));
    await new Promise<void>((r) => redis.listen(18332, "127.0.0.1", () => r()));
    await mk((req, res) => {
      if (req.url?.startsWith("/version")) { res.writeHead(200).end('{"Version":"26.1","ApiVersion":"1.45"}'); return; }
      if (req.url?.startsWith("/containers")) { res.writeHead(200).end('[{"Id":"a"},{"Id":"b"}]'); return; }
      res.writeHead(200).end("[]");
    }, 18333);
    const { probeServiceUnauth } = await import("../src/domain/serviceUnauth.js");
    const dir = await mkdtemp(join(tmpdir(), "su-"));
    const r = await probeServiceUnauth({ host: "127.0.0.1", outputRoot: join(dir, "o"), ports: { redis: 18332, docker: 18333 }, timeoutMs: 3000, services: ["redis", "docker"] });
    const redisF = r.findings.find((f) => f.id === "redis");
    const dockerF = r.findings.find((f) => f.id === "docker");
    expect(redisF?.state).toBe("unauth-access");
    expect(redisF?.extras?.db0Keys).toBe("7");
    expect(dockerF?.state).toBe("unauth-access");
    expect(dockerF?.extras?.containers).toBe(2);
  });
});

describe("actuator exploitation", () => {
  it("mines env secrets and executes SpEL through the gateway route", { timeout: 20000 }, async () => {
    const routes = new Map<string, unknown>();
    await mk(async (req, res) => {
      const u = req.url ?? "";
      if (u === "/actuator") { res.writeHead(200).end('{"_links":{"self":{},"env":{},"gateway/routes":{},"health":{}}}'); return; }
      if (u === "/actuator/env") { res.writeHead(200).end(JSON.stringify({ propertySources: [{ name: "systemEnvironment", properties: { "spring.datasource.password": { value: "hunter2-db-pass" }, "PATH": { value: "/usr/bin" } } }] })); return; }
      if (u === "/actuator/gateway/routes" && req.method === "GET") { res.writeHead(200).end(JSON.stringify([...routes.keys()].map((id) => ({ route_id: id })))); return; }
      if (u === "/actuator/gateway/routes/velric-rce" && req.method === "POST") { await body(req); routes.set("velric-rce", 1); res.writeHead(201).end("{}"); return; }
      if (u === "/actuator/gateway/routes/velric-rce" && req.method === "DELETE") { routes.delete("velric-rce"); res.writeHead(200).end(); return; }
      if (u === "/actuator/gateway/routes/velric-rce" && req.method === "GET") { res.writeHead(200).end(JSON.stringify({ route_id: "velric-rce", filters: [{ args: { _genkey_1: "uid=0(root) gid=0(root) groups=0(root)" } }] })); return; }
      if (u === "/actuator/gateway/refresh") { res.writeHead(200).end("{}"); return; }
      if (u === "/actuator/heapdump") { res.writeHead(200).end(Buffer.from("xx\u0000spring.datasource.password=heap-secret-99\u0000zz AKIAABCDEFGHIJKLMNOP")); return; }
      res.writeHead(404).end("nf");
    }, 18334);
    const { probeActuator } = await import("../src/domain/actuatorExploit.js");
    const dir = await mkdtemp(join(tmpdir(), "act-"));
    const r = await probeActuator({ baseUrl: "http://127.0.0.1:18334", outputRoot: join(dir, "o"), maxHeapBytes: 1024 * 1024 });
    expect(r.secrets.some((s) => s.key === "spring.datasource.password")).toBe(true);
    expect(r.secrets.some((s) => s.key === "aws-access-key")).toBe(true);
    expect(r.rce?.output).toContain("uid=0");
    expect(r.routes).not.toContain("velric-rce"); // temporary route cleaned up
  });
});

describe("paywall enforcement", () => {
  it("reports no-server-gate when premium data is served anonymously", { timeout: 20000 }, async () => {
    await mk((req, res) => {
      if (req.url === "/api/me") { res.writeHead(200, { "content-type": "application/json" }).end('{"user":"a","plan":"free"}'); return; }
      res.writeHead(200, { "content-type": "application/json" }).end('{"pro":true,"rows":[1,2,3],"export":"csv"}');
    }, 18335);
    const { probeEntitlementBypass } = await import("../src/domain/entitlementBypass.js");
    const dir = await mkdtemp(join(tmpdir(), "ent-"));
    const r = await probeEntitlementBypass({ premiumUrl: "http://127.0.0.1:18335/api/pro/export", accountUrl: "http://127.0.0.1:18335/api/me", outputRoot: join(dir, "o") });
    expect(r.plan).toBe("free");
    expect(r.verdicts[0]?.verdict).toBe("no-server-gate");
    expect(r.exploitable).toBe(true);
  });

  it("reports server-enforced when the premium path blocks with 403", { timeout: 20000 }, async () => {
    await mk((req, res) => {
      if (req.url === "/api/me") { res.writeHead(200).end('{"plan":"free"}'); return; }
      res.writeHead(403).end("upgrade required");
    }, 18336);
    const { probeEntitlementBypass } = await import("../src/domain/entitlementBypass.js");
    const dir = await mkdtemp(join(tmpdir(), "ent2-"));
    const r = await probeEntitlementBypass({ premiumUrl: "http://127.0.0.1:18336/pro", accountUrl: "http://127.0.0.1:18336/api/me", outputRoot: join(dir, "o") });
    expect(r.exploitable).toBe(false); // forged claims also 403 → server really enforces
    expect(r.verdicts.find((v) => v.name === "free-account-access")?.status).toBe(403);
  });
});

describe("billing tampering", () => {
  it("flags accepted-as-is when the order stores the client price", { timeout: 20000 }, async () => {
    const orders = new Map<string, string>();
    await mk(async (req, res) => {
      if (req.method === "POST") {
        const b = JSON.parse(await body(req)) as { amount: number; currency: string };
        const id = `ord${orders.size + 1}`;
        orders.set(id, JSON.stringify({ id, amount: b.amount, currency: b.currency }));
        res.writeHead(201, { "content-type": "application/json" }).end(JSON.stringify({ id }));
        return;
      }
      const id = (req.url ?? "").split("/").pop()!;
      const o = orders.get(id);
      if (!o) { res.writeHead(404).end(); return; }
      res.writeHead(200, { "content-type": "application/json" }).end(o);
    }, 18337);
    const { probeBillingTamper } = await import("../src/domain/billingTamper.js");
    const dir = await mkdtemp(join(tmpdir(), "bill-"));
    const r = await probeBillingTamper({ url: "http://127.0.0.1:18337/checkout", bodyTemplate: '{"amount":{AMOUNT},"currency":"{CURRENCY}","qty":{QTY}}', amount: 1999, currency: "USD", orderUrl: "http://127.0.0.1:18337/orders/{ID}", outputRoot: join(dir, "o") });
    expect(r.accepted.map((c) => c.vector)).toEqual(expect.arrayContaining(["amount-zero", "amount-one-cent"]));
    expect(r.accepted[0]?.storedAmount).toBe("0");
  });
});

describe("oauth redirect matrix", () => {
  it("flags an accepted suffix-evil redirect", { timeout: 20000 }, async () => {
    await mk((req, res) => {
      const q = new URL(req.url ?? "/", "http://x");
      const uri = q.searchParams.get("redirect_uri") ?? "";
      const state = q.searchParams.get("state");
      let target: URL | null = null;
      try { target = new URL(uri); } catch { target = null; }
      // naive suffix matching: anything STARTING with the legit origin passes
      if (target && (target.origin === "https://app.legit.test" || uri.startsWith("https://app.legit.test"))) {
        res.writeHead(302, { location: uri + (state ? `#state=${state}` : "") }).end();
      } else {
        res.writeHead(400).end("invalid redirect_uri");
      }
    }, 18338);
    const { probeOAuthBypass } = await import("../src/domain/oauthBypass.js");
    const dir = await mkdtemp(join(tmpdir(), "oa-"));
    const r = await probeOAuthBypass({ authzUrl: "http://127.0.0.1:18338/authorize?client_id=c&response_type=code&redirect_uri={REDIRECT}&state={STATE}", redirect: "https://app.legit.test/cb", outputRoot: join(dir, "o") });
    expect(r.honest.host).toBe("app.legit.test");
    expect(r.vectors.find((v) => v.name === "subdomain-suffix")?.verdict).toBe("accepted");
    expect(r.takeoverRisk).toBe(true);
  });
});

describe("asar unpack", () => {
  it("extracts files and localizes the license check", { timeout: 20000 }, async () => {
    const files: Record<string, Buffer> = {
      "package.json": Buffer.from('{"name":"demo","version":"1.0.0","main":"main.js"}'),
      "main.js": Buffer.from('const ok = licenseKey === "AAAA-BBBB";\nconst api = "https://api.demo.test/v1/activate";\nif (!ok) showPaywall();\n'),
    };
    const header: Record<string, unknown> = { files: {} };
    let offset = 0;
    for (const [name, buf] of Object.entries(files)) {
      (header.files as Record<string, unknown>)[name] = { size: buf.length, offset: String(offset) };
      offset += buf.length;
    }
    const headerBuf = Buffer.from(JSON.stringify(header));
    const pad = (4 - (headerBuf.length % 4)) % 4;
    const out = Buffer.concat([Buffer.alloc(8), headerBuf, Buffer.alloc(pad), ...Object.values(files)]);
    out.writeUInt32LE(4, 0);
    out.writeUInt32LE(headerBuf.length + pad, 4);
    const dir = await mkdtemp(join(tmpdir(), "asar-"));
    const asarPath = join(dir, "app.asar");
    await writeFile(asarPath, out);
    const { unpackAsar } = await import("../src/domain/asarUnpack.js");
    const r = await unpackAsar({ asarPath, outputRoot: join(dir, "o") });
    expect(r.entryCount).toBe(2);
    expect(r.extracted).toBe(2);
    expect(r.package.name).toBe("demo");
    expect(r.findings.some((f) => f.kind === "local-check")).toBe(true);
    expect(r.findings.some((f) => f.kind === "remote-check" && f.endpoint?.includes("/activate"))).toBe(true);
    const extracted = await readFile(join(dir, "o", "asar", "main.js"), "utf8");
    expect(extracted).toContain("licenseKey");
  });
});
