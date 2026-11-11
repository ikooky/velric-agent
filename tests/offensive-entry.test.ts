import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import net from "node:net";

const servers: (http.Server | net.Server)[] = [];
const mk = (h: http.RequestListener, port: number): Promise<void> => new Promise((r) => { const s = http.createServer(h); servers.push(s); s.listen(port, "127.0.0.1", () => r()); });
const mktcp = (h: (s: net.Socket) => void, port: number): Promise<void> => new Promise((r) => { const s = net.createServer(h); servers.push(s); s.listen(port, "127.0.0.1", () => r()); });
afterAll(() => { for (const s of servers) s.close(); });
const body = async (req: http.IncomingMessage): Promise<string> => { let b = ""; for await (const c of req) b += c; return b; };

describe("user enumeration", () => {
  it("separates existing from absent accounts via the oracle", { timeout: 20000 }, async () => {
    await mk(async (req, res) => {
      const b = new URLSearchParams(await body(req));
      const user = b.get("user") ?? "";
      if (user === "alice" || user === "known") { res.writeHead(401).end("Invalid password"); return; }
      res.writeHead(401).end("User not found");
    }, 18371);
    const { probeUserEnum } = await import("../src/domain/userEnum.js");
    const dir = await mkdtemp(join(tmpdir(), "ue-"));
    const r = await probeUserEnum({ url: "http://127.0.0.1:18371/login", bodyTemplate: "user={USER}&pass={PASS}", mode: "login", knownUser: "known", candidates: ["alice", "bob"], outputRoot: join(dir, "o") });
    expect(r.oracle).toBe(true);
    expect(r.existing).toEqual(["alice"]);
  });
});

describe("password spray", () => {
  it("sprays within the per-user budget and stops on success", { timeout: 20000 }, async () => {
    await mk(async (req, res) => {
      const b = new URLSearchParams(await body(req));
      if (b.get("user") === "alice" && b.get("pass") === "Spring2025") { res.writeHead(200, { "content-type": "application/json" }).end('{"token":"t"}'); return; }
      res.writeHead(401, { "content-type": "application/json" }).end('{"error":"invalid"}');
    }, 18372);
    const { sprayPasswords } = await import("../src/domain/spray.js");
    const dir = await mkdtemp(join(tmpdir(), "sp-"));
    const r = await sprayPasswords({ url: "http://127.0.0.1:18372/login", bodyTemplate: "user={USER}&pass={PASS}", users: ["alice", "bob"], passwords: ["Winter2024", "Spring2025", "Extra1"], outputRoot: join(dir, "o"), delayMs: 0, maxPerUser: 3 });
    expect(r.hits.find((h) => h.user === "alice")?.classification).toBe("ok");
    expect(r.hits.find((h) => h.user === "alice")?.password).toBe("Spring2025");
  });
});

describe("hash crack", () => {
  it("recovers a rule-mutated dictionary password", { timeout: 20000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "hc-"));
    const md5 = createHash("md5").update("Welcome1").digest("hex");
    const { crackHashes } = await import("../src/domain/hashCrack.js");
    const r = await crackHashes({ hashes: [md5], outputRoot: join(dir, "o") });
    expect(r.cracked[0]).toMatchObject({ plaintext: "Welcome1", algorithm: "md5" });
  });

  it("cracks a Django pbkdf2 hash", { timeout: 30000 }, async () => {
    const { pbkdf2Sync } = await import("node:crypto");
    const salt = "abc123";
    const want = pbkdf2Sync("changeme", salt, 10000, 32, "sha256").toString("base64");
    const dir = await mkdtemp(join(tmpdir(), "hc2-"));
    const { crackHashes } = await import("../src/domain/hashCrack.js");
    const r = await crackHashes({ hashes: [`pbkdf2_sha256$10000$${salt}$${want}`], outputRoot: join(dir, "o") });
    expect(r.cracked[0]?.plaintext).toBe("changeme");
  });
});

describe("signed URL enforcement", () => {
  it("flags signature-stripping acceptance", { timeout: 20000 }, async () => {
    await mk((req, res) => {
      if (!req.url?.startsWith("/f/document.pdf")) { res.writeHead(404).end(); return; }
      res.writeHead(200, { "content-type": "application/pdf" }).end("%PDF-1.4 data");
    }, 18373);
    const { probeSignedUrl } = await import("../src/domain/signedUrl.js");
    const dir = await mkdtemp(join(tmpdir(), "su2-"));
    const r = await probeSignedUrl({ url: "http://127.0.0.1:18373/f/document.pdf?X-Amz-Signature=abc&X-Amz-Expires=60", outputRoot: join(dir, "o") });
    expect(r.cases.find((c) => c.name === "signature-stripped")?.verdict).toBe("signature-ignored");
    expect(r.exploitable).toBe(true);
  });
});

describe("deserialization surface", () => {
  it("detects a Java stream reaching ObjectInputStream", { timeout: 20000 }, async () => {
    await mk((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      const v = u.searchParams.get("data") ?? "";
      if (v.startsWith("rO0AB")) { res.writeHead(500).end("java.io.InvalidClassException: local class incompatible"); return; }
      if (v === "velric-baseline") { res.writeHead(200).end("ok"); return; }
      res.writeHead(200).end(`ok ${v.slice(0, 10)}`);
    }, 18374);
    const { probeDeser } = await import("../src/domain/deserSurface.js");
    const dir = await mkdtemp(join(tmpdir(), "ds-"));
    const r = await probeDeser({ url: "http://127.0.0.1:18374/api?data=x", outputRoot: join(dir, "o") });
    expect(r.exploitable.some((p) => p.format === "java")).toBe(true);
  });
});

describe("smuggling into an admin bypass", () => {
  it("reads the smuggled /admin response through a CL.TE front", { timeout: 20000 }, async () => {
    await mktcp((sock) => {
      let buf = "";
      sock.on("data", (c) => {
        buf += c.toString("latin1");
        if (!buf.includes("\r\n\r\n")) return;
        if (buf.includes("Upgrade: h2c")) {
          sock.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");
          const frame = Buffer.from([0, 1, 0x88, 0x01, 0x05, 0, 0, 0, 1]);
          sock.write(Buffer.from(frame));
          return;
        }
        if (buf.includes("X-Smuggled: clte")) {
          sock.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
          setTimeout(() => sock.write("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nadmin-panel!!"), 30);
          return;
        }
        if (buf.includes("GET /admin")) { sock.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied"); return; }
        sock.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
      });
    }, 18375);
    const { probeSmuggleExploit } = await import("../src/domain/smuggleExploit.js");
    const dir = await mkdtemp(join(tmpdir(), "sm-"));
    const r = await probeSmuggleExploit({ baseUrl: "http://127.0.0.1:18375", targetPath: "/admin", outputRoot: join(dir, "o"), timeoutMs: 1200 });
    expect(r.target.directStatus).toBe(403);
    expect(r.cases.find((c) => c.name === "CL.TE")?.smuggledStatus).toBe(200);
    expect(r.bypass).toBe(true);
  });
});
