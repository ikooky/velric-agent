import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";

const servers: http.Server[] = [];
const mk = (h: http.RequestListener, port: number): Promise<void> => new Promise((r) => {
  const s = http.createServer(h); servers.push(s); s.listen(port, "127.0.0.1", () => r());
});
afterAll(() => { for (const s of servers) s.close(); });
const body = async (req: http.IncomingMessage): Promise<string> => { let b = ""; for await (const c of req) b += c; return b; };

describe("path confusion auth bypass", () => {
  it("finds the trailing-slash bypass through a soft-404 wall", { timeout: 30000 }, async () => {
    await mk((req, res) => {
      const p = (req.url ?? "").split("?")[0]!;
      if (p === "/admin") { res.writeHead(401).end("login required"); return; }
      if (p === "/admin/") { res.writeHead(200).end("<h1>Admin dashboard</h1><p>users: 42</p>"); return; }
      res.writeHead(200).end("<html><body>not found</body></html>");
    }, 18351);
    const { probePathBypass } = await import("../src/domain/pathAuthBypass.js");
    const dir = await mkdtemp(join(tmpdir(), "pb-"));
    const r = await probePathBypass({ protectedUrl: "http://127.0.0.1:18351/admin", outputRoot: join(dir, "o") });
    expect(r.bypassed.map((v) => v.name)).toContain("trailing-slash");
    expect(r.bypassed.find((v) => v.name === "trailing-slash")?.evidence).toContain("200");
  });
});

describe("2FA bypass", () => {
  it("flags pre-OTP resource access and OTP replay", { timeout: 30000 }, async () => {
    await mk(async (req, res) => {
      if (req.url === "/login" && req.method === "POST") {
        await body(req);
        res.writeHead(200, { "set-cookie": "preotp=1; Path=/", "content-type": "application/json" }).end('{"otpRequired":true}');
        return;
      }
      if (req.url === "/verify" && req.method === "POST") { await body(req); res.writeHead(200).end('{"ok":true}'); return; }
      if (req.url === "/api/secret") {
        if ((req.headers.cookie ?? "").includes("preotp=1")) { res.writeHead(200).end("secret data"); return; }
        res.writeHead(302, { location: "/login" }).end();
        return;
      }
      res.writeHead(404).end();
    }, 18352);
    const { probeTwoFaBypass } = await import("../src/domain/twoFaBypass.js");
    const dir = await mkdtemp(join(tmpdir(), "2fa-"));
    const r = await probeTwoFaBypass({ loginUrl: "http://127.0.0.1:18352/login", verifyUrl: "http://127.0.0.1:18352/verify", protectedUrl: "http://127.0.0.1:18352/api/secret", bodyTemplate: "user={USER}&pass={PASS}&code={CODE}", user: "u", pass: "p", code: "123456", outputRoot: join(dir, "o") });
    expect(r.probes.find((p) => p.name === "otp-step-skip")?.verdict).toBe("bypass");
    expect(r.probes.find((p) => p.name === "otp-replay")?.verdict).toBe("reusable");
    expect(r.exploitable).toBe(true);
  });
});

describe("reset depth", () => {
  it("flags token predictability, host canary and reuse", { timeout: 30000 }, async () => {
    await mk(async (req, res) => {
      if (req.url === "/reset" && req.method === "POST") { await body(req); res.writeHead(200).end("sent"); return; }
      if (req.url?.startsWith("/reset/form")) { res.writeHead(200).end('<html><img src="https://cdn.tracker.test/p.gif"><a href="https://help.test/x">?</a></html>'); return; }
      if (req.url?.startsWith("/submit") && req.method === "POST") { await body(req); res.writeHead(200).end("ok"); return; }
      if (req.url === "/login" && req.method === "POST") { await body(req); res.writeHead(200).end("ok"); return; }
      res.writeHead(404).end();
    }, 18353);
    const { probeResetDeep } = await import("../src/domain/resetDeep.js");
    const dir = await mkdtemp(join(tmpdir(), "rd-"));
    const r = await probeResetDeep({
      requestUrl: "http://127.0.0.1:18353/reset", bodyTemplate: "email={EMAIL}", email: "a@b.test",
      token: "1699999999000", submitUrl: "http://127.0.0.1:18353/reset/form?t={TOKEN}",
      loginUrl: "http://127.0.0.1:18353/login", outputRoot: join(dir, "o"),
    });
    expect(r.probes.find((p) => p.name === "token-shape")?.verdict).toBe("predictable");
    expect(r.probes.find((p) => p.name === "host-header-poison")?.verdict).toBe("poison-suspect");
    expect(r.refererHosts).toContain("cdn.tracker.test");
    expect(r.probes.find((p) => p.name === "token-reuse")?.verdict).toBe("reusable");
  });
});

describe("cloud storage", () => {
  it("reports public list and write-enabled", { timeout: 30000 }, async () => {
    await mk((req, res) => {
      if (req.method === "PUT") { res.writeHead(200).end(); return; }
      if (req.method === "DELETE") { res.writeHead(204).end(); return; }
      res.writeHead(200).end("<ListBucketResult><KeyCount>2</KeyCount><Contents><Key>a.txt</Key></Contents><Contents><Key>b.txt</Key></Contents></ListBucketResult>");
    }, 18354);
    const { probeCloudStorage } = await import("../src/domain/cloudStorage.js");
    const dir = await mkdtemp(join(tmpdir(), "cs-"));
    const r = await probeCloudStorage({ buckets: ["demo"], outputRoot: join(dir, "o"), endpoint: "http://127.0.0.1:18354", write: true });
    expect(r.findings[0]?.state).toBe("write-enabled");
    expect(r.findings[0]?.keys).toEqual(["a.txt", "b.txt"]);
  });
});

describe("runtime config leak", () => {
  it("extracts a live Stripe key and filters SPA fallback", { timeout: 30000 }, async () => {
    await mk((req, res) => {
      if (req.url === "/config.js") { res.writeHead(200, { "content-type": "application/javascript" }).end('window.CFG={STRIPE:"pk_live_abc1234567890XYZ",API:"https://api.test"}'); return; }
      res.writeHead(200, { "content-type": "text/html" }).end("<html>spa</html>");
    }, 18355);
    const { probeConfigLeak } = await import("../src/domain/configLeak.js");
    const dir = await mkdtemp(join(tmpdir(), "cl-"));
    const r = await probeConfigLeak({ baseUrl: "http://127.0.0.1:18355", outputRoot: join(dir, "o") });
    expect(r.secrets.some((s) => s.kind === "stripe-pk" && s.path === "/config.js")).toBe(true);
    expect(r.files.find((f) => f.path === "/env.js")?.looksLikeConfig).toBe(false);
  });
});

describe("admin post-login RCE", () => {
  it("runs a command through the Jenkins script console", { timeout: 30000 }, async () => {
    await mk(async (req, res) => {
      const auth = req.headers.authorization;
      if (!auth) { res.writeHead(401).end(); return; }
      if (req.url === "/api/json") { res.writeHead(200).end('{"mode":"NORMAL","jobs":[]}'); return; }
      if (req.url === "/crumbIssuer/api/json") { res.writeHead(404).end(); return; }
      if (req.url === "/scriptText" && req.method === "POST") {
        const b = new URLSearchParams(await body(req));
        const script = b.get("script") ?? "";
        res.writeHead(200).end(script.includes("id") ? "uid=0(root) gid=0(root)\n" : "?\n");
        return;
      }
      res.writeHead(404).end();
    }, 18356);
    const { exploitAdmin } = await import("../src/domain/adminRce.js");
    const dir = await mkdtemp(join(tmpdir(), "ar-"));
    const r = await exploitAdmin({ baseUrl: "http://127.0.0.1:18356", panel: "jenkins", user: "admin", pass: "admin", outputRoot: join(dir, "o") });
    expect(r.authenticated).toBe(true);
    expect(r.loot.command).toContain("uid=0");
  });
});

describe("actuator deep reach", () => {
  it("reads system properties via Jolokia and proves the env write path", { timeout: 30000 }, async () => {
    await mk(async (req, res) => {
      const u = req.url ?? "";
      if (u === "/actuator") { res.writeHead(200).end('{"_links":{"self":{}}}'); return; }
      if (u === "/actuator/jolokia/list") { res.writeHead(200).end('{"java.lang":{"type":{"Runtime":{"op":{}}}}}'); return; }
      if (u === "/actuator/jolokia/read/java.lang:type=Runtime/SystemProperties") { res.writeHead(200).end('{"value":{"DB_PASSWORD":"s3cr3t","PATH":"/bin"}}'); return; }
      if (u === "/actuator/jolokia/exec/java.lang:type=Memory/gc") { res.writeHead(200).end('{"value":null}'); return; }
      if (u === "/actuator/env" && req.method === "POST") { await body(req); res.writeHead(200).end('{"name":"logging.level.root"}'); return; }
      if (u === "/actuator/refresh") { res.writeHead(200).end("[]"); return; }
      if (u === "/actuator/loggers") { res.writeHead(200).end('{"levels":["DEBUG"],"loggers":{"ROOT":{"effectiveLevel":"DEBUG"}}}'); return; }
      if (u === "/actuator/sessions") { res.writeHead(200).end('["sess-1"]'); return; }
      if (u === "/actuator/heapdump") { res.writeHead(200).end("x\u0000JSESSIONID=ABCDEF0123456789\u0000y"); return; }
      if (u === "/actuator/configprops") { res.writeHead(200).end('{"contexts":{"c":{"beans":{"db":{"properties":{"url":"jdbc:mysql://db:3306/app"}}}}}}'); return; }
      res.writeHead(404).end();
    }, 18357);
    const { exploitActuator } = await import("../src/domain/actuatorRce.js");
    const dir = await mkdtemp(join(tmpdir(), "at-"));
    const r = await exploitActuator({ baseUrl: "http://127.0.0.1:18357", outputRoot: join(dir, "o") });
    expect(r.loot.systemProperties?.some((p) => p.key === "DB_PASSWORD")).toBe(true);
    expect(r.actions.find((a) => a.name === "env-write-refresh")?.evidence).toContain("DEBUG took effect");
    expect(r.loot.sessions).toEqual(["sess-1"]);
    expect(r.loot.heapTokens?.[0]).toContain("JSESSIONID:ABCDEF0123456789");
  });
});

describe("asar patch", () => {
  it("rewrites a license comparison and repacks a readable archive", { timeout: 30000 }, async () => {
    const files: Record<string, Buffer> = {
      "package.json": Buffer.from('{"name":"demo","version":"1.0.0"}'),
      "main.js": Buffer.from('if (licenseKey === "AAAA-BBBB") { activate(); } else { paywall(); }\n'),
    };
    const header: Record<string, unknown> = { files: {} };
    let off = 0;
    for (const [n, b] of Object.entries(files)) { (header.files as Record<string, unknown>)[n] = { size: b.length, offset: String(off) }; off += b.length; }
    const hb = Buffer.from(JSON.stringify(header)); const pad = (4 - hb.length % 4) % 4;
    const raw = Buffer.concat([Buffer.alloc(8), hb, Buffer.alloc(pad), ...Object.values(files)]);
    raw.writeUInt32LE(4, 0); raw.writeUInt32LE(hb.length + pad, 4);
    const dir = await mkdtemp(join(tmpdir(), "ap-"));
    const src = join(dir, "app.asar");
    const dst = join(dir, "patched.asar");
    await writeFile(src, raw);
    const { patchAsar } = await import("../src/domain/asarPatch.js");
    const r = await patchAsar({ asarPath: src, outputPath: dst, patches: [{ file: "main.js", find: 'licenseKey === "AAAA-BBBB"', replace: "true" }] });
    expect(r.applied[0]?.applied).toBe(1);
    expect(r.sha256After).not.toBe(r.sha256Before);
    const { unpackAsar } = await import("../src/domain/asarUnpack.js");
    const u = await unpackAsar({ asarPath: dst, outputRoot: join(dir, "x") });
    expect(u.extracted).toBe(2);
    const { readFile } = await import("node:fs/promises");
    expect(await readFile(join(dir, "x", "asar", "main.js"), "utf8")).toContain("if (true)");
  });
});
