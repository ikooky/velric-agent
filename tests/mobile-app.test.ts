import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import { createHmac, createCipheriv, createHash, randomUUID } from "node:crypto";

const servers: http.Server[] = [];
const mk = (h: http.RequestListener, port: number): Promise<void> => new Promise((r) => { const s = http.createServer(h); servers.push(s); s.listen(port, "127.0.0.1", () => r()); });
afterAll(() => { for (const s of servers) s.close(); });
const body = async (req: http.IncomingMessage): Promise<string> => { let b = ""; for await (const c of req) b += c; return b; };

// —— Envelope cipher (same dual-SHA256 split as the tool) ———
const sha = (b: Buffer): Buffer => createHash("sha256").update(b).digest();
const encrypt = (key: string, plain: string): string => {
  const k = Buffer.from(key, "utf8");
  const salt = Buffer.from("abcdefghijkl");
  const i = Buffer.concat([k, salt]);
  const half = i.length >> 1;
  const l = sha(i).subarray(8, 24);
  const m = Buffer.concat([l, i.subarray(0, half)]);
  const g = Buffer.concat([i.subarray(half), l]);
  const keyOut = Buffer.concat([sha(m).subarray(0, 8), sha(g).subarray(8, 24), sha(m).subarray(24)]);
  const iv = Buffer.concat([sha(g).subarray(0, 4), sha(m).subarray(12, 20), sha(g).subarray(28)]);
  const c = createCipheriv("aes-256-cbc", keyOut, iv);
  return Buffer.concat([salt, c.update(Buffer.from(plain, "utf8")), c.final()]).toString("base64");
};

describe("envelope-break", () => {
  it("cracks the AES envelope with the right candidate key", { timeout: 20000 }, async () => {
    const KEY = "65dc07d1b7915c6b2937432b091837a7";
    const doc = JSON.stringify({ code: 200, data: encrypt(KEY, JSON.stringify({ uid: 1, note: "structure-only" })) });
    const dir = await mkdtemp(join(tmpdir(), "eb-"));
    const f = join(dir, "env.json");
    await writeFile(f, doc);
    const { crackEnvelope } = await import("../src/domain/envelopeBreak.js");
    const r = await crackEnvelope({ response: f, outputRoot: join(dir, "o"), keys: ["wrong-key-123456", KEY] });
    expect(r.cracked).toBe(true);
    expect(r.keyUsed).toBe(KEY);
    expect((r.parsed as { uid?: number })?.uid).toBe(1);
  });

  it("reports failure honestly with only wrong keys", { timeout: 20000 }, async () => {
    const dir = await mkdtemp(join(tmpdir(), "eb2-"));
    const { crackEnvelope } = await import("../src/domain/envelopeBreak.js");
    const r = await crackEnvelope({ response: JSON.stringify({ code: 200, data: encrypt("real-key-aaaaaaaaaaaa", "x") }), outputRoot: join(dir, "o"), keys: ["nope1", "nope2"] });
    expect(r.cracked).toBe(false);
  });
});

describe("app-api signed replay", () => {
  it("signs, calls and decrypts the envelope response", { timeout: 20000 }, async () => {
    const KEY = "65dc07d1b7915c6b2937432b091837a7";
    await mk(async (req, res) => {
      const auth = req.headers.authorization;
      const xak = req.headers["x-api-key"] as string | undefined;
      if (!auth || !xak) { res.writeHead(401).end("no token"); return; }
      const m = /timestamp=(\d+);sign=([0-9a-f]+);nonce=([0-9a-f]+)/.exec(xak);
      if (!m) { res.writeHead(400).end("bad header"); return; }
      const expected = createHmac("sha1", "kaFtkDJRcchRMTI9").update(JSON.stringify({ nonce: m[3], path: req.url?.split("?")[0], timestamp: Number(m[1]), token: auth, userAgent: "okhttp/4.12.0" })).digest("hex");
      if (expected !== m[2]) { res.writeHead(403).end("bad sign"); return; }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ code: 200, data: encrypt(KEY, JSON.stringify({ ok: true, items: [1, 2, 3] })) }));
    }, 18401);
    const dir = await mkdtemp(join(tmpdir(), "aa-"));
    const { callAppApi } = await import("../src/domain/appApi.js");
    const r = await callAppApi({
      outputRoot: join(dir, "o"),
      calls: [{
        name: "probe", url: "http://127.0.0.1:18401/api/app/ping/check",
        scheme: { header: "x-api-key", algo: "sha1", key: "kaFtkDJRcchRMTI9", message: "JSON:{nonce,path,timestamp,token,userAgent}", headerValue: "timestamp={ts};sign={sign};nonce={nonce}" },
        token: "tok-abc", bodyCipherKey: KEY,
      }],
    });
    expect(r.results[0]?.status).toBe(200);
    expect((r.results[0]?.decrypted as { ok?: boolean })?.ok).toBe(true);
  });
});

describe("device-login minting", () => {
  it("finds the accepted field and proves unlimited accounts", { timeout: 20000 }, async () => {
    await mk(async (req, res) => {
      const b = JSON.parse(await body(req)) as Record<string, string>;
      if (typeof b.devId === "string" && b.devId.length > 10) { res.writeHead(200).end(JSON.stringify({ token: "t".repeat(40) })); return; }
      if (typeof b.deviceId === "string") { res.writeHead(200).end(JSON.stringify({ accessToken: "a".repeat(40) })); return; }
      res.writeHead(400).end(JSON.stringify({ error: "bad" }));
    }, 18402);
    const dir = await mkdtemp(join(tmpdir(), "dl-"));
    const { probeDeviceLogin } = await import("../src/domain/deviceLogin.js");
    const r = await probeDeviceLogin({ url: "http://127.0.0.1:18402/login", outputRoot: join(dir, "o") });
    expect(r.working.map((w) => w.field).sort()).toEqual(["devId", "deviceId"]);
    expect(r.unlimited).toBe(true);
  });
});

describe("hls-chain capability proof", () => {
  it("pulls playlist, key, decrypts segments to TS and flags gateway discipline", { timeout: 30000 }, async () => {
    const KEY = Buffer.from("0123456789abcdef");
    const iv = Buffer.alloc(16);
    const enc = (buf: Buffer): Buffer => { const c = createCipheriv("aes-128-cbc", KEY, iv); return Buffer.concat([c.update(buf), c.final()]); };
    const seg = (n: number): Buffer => { const packet = Buffer.alloc(188 * 20); for (let i = 0; i < 20; i++) packet[i * 188] = 0x47; packet.write(`seg${n}`, 10, "latin1"); return enc(packet); };
    await mk((req, res) => {
      const p = req.url ?? "";
      if (p === "/api/app/vid/sec") { res.writeHead(200).end(KEY); return; }
      if (p.startsWith("/api/app/vid/h5/m3u8/")) {
        const path = decodeURIComponent(p.slice("/api/app/vid/h5/m3u8/".length));
        // capability discipline: only the known path serves content, bogus → error
        if (!path.startsWith("valid/")) { res.writeHead(200, { "content-type": "application/vnd.apple.mpegurl" }).end("#EXTM3U\n#EXT-X-ENDLIST\n"); return; }
        void 0;
        res.writeHead(200, { "content-type": "application/vnd.apple.mpegurl" }).end(`#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI="/api/app/vid/sec"\n#EXTINF:10,\nhttp://127.0.0.1:18403/cdn/s0.ts?md=abc\n#EXTINF:5,\nhttp://127.0.0.1:18403/cdn/s1.ts?md=def\n`);
        return;
      }
      if (p.startsWith("/cdn/")) {
        if (p.includes("?")) { res.writeHead(200).end(seg(Number(p.match(/s(\d)\.ts/)?.[1] ?? 0))); return; }
        res.writeHead(403).end("no signature"); return;
      }
      res.writeHead(404).end();
    }, 18403);
    const dir = await mkdtemp(join(tmpdir(), "hc-"));
    const { extractHlsChain } = await import("../src/domain/hlsChain.js");
    const r = await extractHlsChain({
      gatewayTemplate: "http://127.0.0.1:18403/api/app/vid/h5/m3u8/{PATH}",
      playlistPathOrUrl: "valid/ep1.m3u8",
      keyUrl: "http://127.0.0.1:18403{PATH}",
      outputRoot: join(dir, "o"),
      maxSegments: 2,
      probeArbitrary: true,
    });
    expect(r.segments).toBe(2);
    expect(r.keyBytes).toBe(16);
    expect(r.decrypted.length).toBe(2);
    expect(r.decrypted[0]?.syncOk).toBe(true);
    expect(r.segmentUrlSigned).toBe(true);
    expect(r.arbitraryPathSigned).toBe(false); // bogus path returned bare playlist with 0 segments — treated as not signed
  });
});

describe("flutter-analyze static layer", () => {
  it("extracts domains, routes and dart classes from a libapp-shaped buffer", { timeout: 30000 }, async () => {
    // Fabricated libapp.so: ELF magic + printable pool with app-like strings.
    const strings = [
      "package:sample_app/api_service/vid_service.dart",
      "https://api.example-backbone.net",
      "https://cdn.example-backbone.net/api/app/ping/check",
      "/api/app/vid/h5/m3u8/",
      "/media/drama/feed",
      "/mine/login",
      "interfaceKey=\"abcdef1234567890abcdef1234567890\"",
    ].join("\n");
    const buf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(64), Buffer.from(strings, "latin1")]);
    const dir = await mkdtemp(join(tmpdir(), "fa-"));
    const so = join(dir, "libapp.so");
    await writeFile(so, buf);
    const { analyzeFlutter } = await import("../src/domain/flutterAnalyze.js");
    const r = await analyzeFlutter({ apkOrSo: so, outputRoot: join(dir, "o") });
    expect(r.counts.domain).toBeGreaterThan(0);
    expect(r.findings.some((f) => f.kind === "route" && f.value.includes("/api/app/"))).toBe(true);
    expect(r.findings.some((f) => f.kind === "dart-class" && f.value.includes("vid_service.dart"))).toBe(true);
    expect(r.findings.some((f) => f.kind === "key" && f.value.includes("abcdef1234"))).toBe(true);
  });
});
