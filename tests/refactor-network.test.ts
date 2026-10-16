import { afterEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { MockAgent, ProxyAgent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { ProxyPool } from "../src/domain/proxyPool.js";
import { acquire } from "../src/domain/rateLimit.js";
import { fetchUrl, setGlobalRateLimit, setGlobalProxyPool } from "../src/adapters/http.js";
import { withExecution, receipts } from "../src/core/execution.js";
import net from "node:net";
import tls from "node:tls";
import { Duplex } from "node:stream";
class WireSocket extends Duplex {
  written: Buffer[] = [];
  constructor(private readonly reply: (b: Buffer, s: WireSocket) => void) { super(); }
  _read() {};
  _write(b: Buffer, _encoding: string, done: (e?: Error | null) => void) { this.written.push(Buffer.from(b)); this.reply(Buffer.from(b), this); done(); }
}
const H = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
afterEach(() => vi.useRealTimers());
describe("native network regressions", () => {
  it("C07 raw HTTP ignores informational headers and decodes chunked bodies", async () => {
    vi.spyOn(net, "connect").mockImplementation((() => { const s = new WireSocket((_b, x) => queueMicrotask(() => x.push("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"))); queueMicrotask(() => s.emit("connect")); return s; }) as any);
    try { const { rawHttpExchange } = await import("../src/adapters/rawTunnel.js"); const r = await rawHttpExchange("http://network.invalid", Buffer.from("GET / HTTP/1.1\r\nHost: network.invalid\r\n\r\n")); expect(r).toMatchObject({ status: 200, body: "body", complete: true }); }
    finally { vi.restoreAllMocks(); }
  });
  it("C07 header parser refuses an oversized complete header rather than treating it as valid", async () => {
    const { readSocket } = await import("../src/adapters/rawTunnel.js"); const s: any = new WireSocket(() => {});
    const p = readSocket(s, b => { const i = b.indexOf("\r\n\r\n"); return i < 0 ? -1 : i + 4; }, 500, 32);
    s.push("HTTP/1.1 101 Switching Protocols\r\nX-Large: " + "x".repeat(100) + "\r\n\r\n");
    await expect(p).rejects.toThrow(/limit/); s.destroy();
  });
  it("C01 SOCKS5 authentication and domain target use only the proxy socket", async () => {
    const frames: Buffer[] = [];
    const direct = vi.spyOn(net, "connect").mockImplementation((() => { const s = new WireSocket((b, x) => {
      frames.push(b); queueMicrotask(() => x.push(frames.length === 1 ? Buffer.from([5, 2]) : frames.length === 2 ? Buffer.from([1, 0]) : Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])));
    }); queueMicrotask(() => s.emit("connect")); return s; }) as any);
    try {
      const { openTunnel } = await import("../src/adapters/rawTunnel.js"); const s = await openTunnel({ host: "network.invalid", port: 443, proxy: "socks5://u:p@socks-proxy.invalid:1080", timeoutMs: 500 }); s.destroy();
      expect(direct.mock.calls[0]?.[0]).toMatchObject({ host: "socks-proxy.invalid", port: 1080 });
      expect([...frames[1]!]).toEqual([1, 1, 117, 1, 112]); expect(frames[2]!.subarray(5, -2).toString()).toBe("network.invalid");
    } finally { vi.restoreAllMocks(); }
  });
  it("C07 invalid WebSocket Accept stays inconclusive instead of accepted", async () => {
    vi.spyOn(net, "connect").mockImplementation((() => { const s = new WireSocket((_b, x) => queueMicrotask(() => x.push("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n"))); queueMicrotask(() => s.emit("connect")); return s; }) as any);
    const { mkdtemp, rm } = await import("node:fs/promises"); const root = await mkdtemp(`${process.env.TMPDIR}/bad-ws-network-`);
    try { const { probeWsOrigin } = await import("../src/domain/wsOrigin.js"); const r = await probeWsOrigin({ url: "ws://network.invalid", outputRoot: root });
      expect(r).toMatchObject({ vulnerable: false, crossOriginAccepted: false, outcome: "inconclusive" }); expect(r.variants.every(v => v.err === "invalid-websocket-handshake")).toBe(true);
    } finally { vi.restoreAllMocks(); await rm(root, { recursive: true, force: true }); }
  });
  it("C01 global proxy pools also own raw tunnel selection and fail closed", async () => {
    const pool = new ProxyPool({ proxies: ["http://global-proxy.invalid:8080"], failThreshold: 1 }); setGlobalProxyPool(pool);
    const direct = vi.spyOn(net, "connect").mockImplementation((() => { const s = new WireSocket((_b, x) => queueMicrotask(() => x.push("HTTP/1.1 200 Connected\r\n\r\n"))); queueMicrotask(() => s.emit("connect")); return s; }) as any);
    try {
      const { openTunnel } = await import("../src/adapters/rawTunnel.js"); const s = await openTunnel({ host: "network.invalid", port: 443, timeoutMs: 100 }); s.destroy();
      expect(direct.mock.calls[0]?.[0]).toMatchObject({ host: "global-proxy.invalid" });
      pool.reportFailure("http://global-proxy.invalid:8080");
      await expect(openTunnel({ host: "network.invalid", port: 443, timeoutMs: 100 })).rejects.toThrow(/exhausted/);
      expect(direct).toHaveBeenCalledTimes(1);
    } finally { setGlobalProxyPool(undefined); vi.restoreAllMocks(); }
  });
  it("G03 unavailable transport without a request start never creates a receipt", async () => {
    const prior = getGlobalDispatcher();
    setGlobalDispatcher({ dispatch(_o: unknown, h: any) { queueMicrotask(() => h.onError(new Error("unavailable"))); return false; } } as any);
    try { await withExecution({ tool: "network-test" }, async () => {
      await fetchUrl("http://network.invalid/no-connect", { method: "POST", body: "x" }); expect(receipts()).toHaveLength(0);
    }); } finally { setGlobalDispatcher(prior); }
  });
  it("G03 client-rejected requests never create transmission receipts", async () => {
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    try { await withExecution({ tool: "network-test" }, async () => {
      const r = await fetchUrl("http://network.invalid/unsent", { method: "GET", body: "forbidden" });
      expect(r.status).toBe(0); expect(receipts()).toHaveLength(0);
    }); } finally { setGlobalDispatcher(prior); await mock.close(); }
  });
  it("E02 follow redirects records each transmitted hop and strips cross-origin credential headers", async () => {
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    mock.get("http://network.invalid").intercept({ path: "/start" }).reply(302, "redirect", { headers: { location: "http://other.invalid/final", "set-cookie": "sid=first; Path=/" } });
    let headers: any;
    mock.get("http://other.invalid").intercept({ path: "/final" }).reply(opts => { headers = opts.headers; return { statusCode: 200, data: "final" }; });
    try { await withExecution({ tool: "network-test" }, async () => {
      const r = await fetchUrl("http://network.invalid/start", { redirect: "follow", headers: { "x-api-key": "private", cookie: "sid=secret" } });
      expect(r.finalUrl).toBe("http://other.invalid/final"); expect(JSON.stringify(headers)).not.toContain("private"); expect(JSON.stringify(headers)).not.toContain("sid=secret");
      expect(receipts().map(x => x.status)).toEqual([302, 200]);
    }); } finally { setGlobalDispatcher(prior); await mock.close(); }
  });
  it("C01 port scan uses CONNECT instead of direct target and preserves inconclusive failures", async () => {
    const direct = vi.spyOn(net, "connect").mockImplementation((() => {
      const s = new WireSocket((b, socket) => queueMicrotask(() => socket.push(b.toString().startsWith("CONNECT network.invalid:443 ") ? "HTTP/1.1 200 Connected\r\n\r\n" : "HTTP/1.1 502 Tunnel failed\r\n\r\n")));
      queueMicrotask(() => s.emit("connect")); return s;
    }) as any);
    const { mkdtemp, rm } = await import("node:fs/promises"); const root = await mkdtemp(`${process.env.TMPDIR}/ports-network-`);
    try {
      const { scanPorts } = await import("../src/domain/portScan.js"); const r = await scanPorts({ host: "network.invalid", ports: [443, 444], outputRoot: root, proxy: "http://port-proxy.invalid:8080", timeoutMs: 100 });
      expect(r.open.map(o => o.port)).toEqual([443]); expect(direct.mock.calls.every(c => (c[0] as any).host === "port-proxy.invalid")).toBe(true);
      expect(r).toMatchObject({ transport: "proxy", outcomes: [{ port: 443, outcome: "open" }, { port: 444, outcome: "inconclusive" }] });
    } finally { vi.restoreAllMocks(); await rm(root, { recursive: true, force: true }); }
  });
  it("C01 httpProbe TLS certificate peek uses the same configured proxy and returns completeness", async () => {
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    vi.spyOn(ProxyAgent.prototype, "dispatch").mockImplementation(((_opts: any, h: any) => { h.onConnect(() => {}); h.onHeaders(200, [], () => {}, "OK"); h.onData(Buffer.from("<title>ok</title>")); h.onComplete([]); return true; }) as any);
    const direct = vi.spyOn(net, "connect").mockImplementation((() => { const s = new WireSocket((_b, x) => queueMicrotask(() => x.push("HTTP/1.1 200 Connected\r\n\r\n"))); queueMicrotask(() => s.emit("connect")); return s; }) as any);
    vi.spyOn(tls, "connect").mockImplementation((() => { const s: any = new WireSocket(() => {}); s.getPeerCertificate = () => ({ subject: { CN: "network.invalid" }, subjectaltname: "DNS:alias.invalid" }); queueMicrotask(() => s.emit("secureConnect")); return s; }) as any);
    try {
      const { httpProbe } = await import("../src/application/probe.js");
      const r = await httpProbe({ url: "https://network.invalid/page", proxy: "http://probe-proxy.invalid:8080", timeoutMs: 100 });
      expect(r.tlsSans).toContain("alias.invalid"); expect(direct.mock.calls.every(c => (c[0] as any).host === "probe-proxy.invalid")).toBe(true);
      expect(r).toMatchObject({ complete: true, truncated: false, finalUrl: "https://network.invalid/page" });
    } finally { vi.restoreAllMocks(); setGlobalDispatcher(prior); await mock.close(); }
  });
  it("F05 DNS tool uses the shared resolver with partial errors", async () => {
    const dns = (await import("node:dns")).promises;
    vi.spyOn(dns.Resolver.prototype, "setServers").mockImplementation(() => {});
    vi.spyOn(dns.Resolver.prototype, "resolve4").mockResolvedValue(["192.0.2.10"] as any);
    vi.spyOn(dns.Resolver.prototype, "resolve6").mockRejectedValue(Object.assign(new Error("timed out"), { code: "ETIMEOUT" }));
    vi.spyOn(dns.Resolver.prototype, "resolveCname").mockResolvedValue(["alias.invalid"]);
    const system = vi.spyOn(dns, "resolve4").mockResolvedValue([]);
    try {
      const { resolveHost } = await import("../src/application/dns.js");
      expect(await resolveHost("network.invalid", ["192.0.2.53"])).toMatchObject({ answers: [{ type: "A", value: "192.0.2.10" }, { type: "CNAME", value: "alias.invalid" }], error: "AAAA: timed out" });
      expect(system).not.toHaveBeenCalled();
    } finally { vi.restoreAllMocks(); }
  });
  it("H04 proxy pool rotates each attempt, reports transport failure, and fails closed on exhaustion", async () => {
    const pool = new ProxyPool({ proxies: ["http://p1.invalid:8080", "http://p2.invalid:8080"], failThreshold: 1 });
    const success = vi.spyOn(pool, "reportSuccess"); const failure = vi.spyOn(pool, "reportFailure");
    let count = 0;
    vi.spyOn(ProxyAgent.prototype, "dispatch").mockImplementation(((_opts: any, h: any) => {
      count++; h.onConnect(() => {});
      if (count === 1) setImmediate(() => h.onError(new Error("proxy unavailable")));
      else { h.onHeaders(200, [], () => {}, "OK"); h.onData(Buffer.from("ok")); h.onComplete([]); }
      return true;
    }) as any);
    try {
      const r = await fetchUrl("http://network.invalid/pool", { proxyPool: pool }); expect(r.status).toBe(200);
      expect(failure).toHaveBeenCalledWith("http://p1.invalid:8080"); expect(success).toHaveBeenCalledWith("http://p2.invalid:8080");
      pool.reportFailure("http://p2.invalid:8080");
      expect((await fetchUrl("http://network.invalid/no-direct", { proxyPool: pool })).failureKind).toBe("proxy-exhausted"); expect(count).toBe(2);
    } finally { vi.restoreAllMocks(); }
  });
  it("C07 smuggle preserves each raw path and labels CL+TE acceptance only as a candidate", async () => {
    const requests: string[] = [];
    vi.spyOn(net, "connect").mockImplementation((() => {
      const s = new WireSocket((b, socket) => { requests.push(b.toString()); const status = b.toString().startsWith("GET") ? 404 : 200; queueMicrotask(() => socket.push(`HTTP/1.1 ${status} fixture\r\nContent-Length: 2\r\n\r\nok`)); });
      queueMicrotask(() => s.emit("connect")); return s;
    }) as any);
    const { mkdtemp, rm } = await import("node:fs/promises"); const root = await mkdtemp(`${process.env.TMPDIR}/smuggle-network-`);
    try {
      const { probeSmuggle } = await import("../src/domain/smuggle.js");
      const r = await probeSmuggle({ baseUrl: "http://network.invalid/app", outputRoot: root, timeoutMs: 100 });
      expect(requests.some(s => s.startsWith("GET /app/x/../healthz-velric HTTP/1.1"))).toBe(true);
      expect(requests.some(s => s.startsWith("POST /app/healthz-velric HTTP/1.1"))).toBe(true);
      expect(r).toMatchObject({ confirmed: false });
      expect(r.differentials.find(d => d.dimension === "CL+TE")).toMatchObject({ outcome: "candidate" });
      expect((r as any).attempts.every((a: any) => a.requestHash && a.responseHash && a.complete)).toBe(true);
    } finally { vi.restoreAllMocks(); await rm(root, { recursive: true, force: true }); }
  });
  it("C05 releases FIFO after a slower rate update and removes cancelled work", async () => {
    vi.useFakeTimers(); vi.setSystemTime(100000);
    const seen: number[] = []; const key = "fifo-refactor";
    await acquire(key, { rps: 10 }).promise;
    const cancelled = acquire(key, { rps: 10 });
    const rejection = cancelled.promise.catch(e => e.name);
    const next = acquire(key, { rps: 1 }).promise.then(() => seen.push(Date.now()));
    cancelled.cancel();
    await vi.advanceTimersByTimeAsync(100);
    expect(seen).toEqual([]);
    await vi.advanceTimersByTimeAsync(900); await next;
    expect(seen).toEqual([101000]);
    expect(await rejection).toBe("AbortError");
  });
  it("C04 hashes exactly the stored bytes and marks a bounded body incomplete", async () => {
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    mock.get("http://network.invalid").intercept({ path: "/cap" }).reply(200, "abcdefgh");
    try {
      const r = await fetchUrl("http://network.invalid/cap", { maxBytes: 4 });
      expect(r.body).toBe("abcd"); expect(r.bytes).toBe(4); expect(r.sha256).toBe(H("abcd"));
      expect(r).toMatchObject({ ok: false, complete: false, truncated: true, storedBytes: 4, storedHash: H("abcd"), receivedBytes: 8 });
    } finally { setGlobalDispatcher(prior); await mock.close(); }
  });
  it("C04 treats a partial stream as failure and retries idempotent requests", async () => {
    const prior = getGlobalDispatcher(); let attempts = 0;
    const dispatcher = { dispatch(_options: unknown, h: any) {
      attempts++;
      h.onConnect(() => {});
      h.onHeaders(200, [Buffer.from("content-type"), Buffer.from("text/plain")], () => {}, "OK");
      h.onData(Buffer.from("prefix"));
      setImmediate(() => h.onError(new Error("broken-stream")));
      return true;
    } };
    setGlobalDispatcher(dispatcher as any);
    try {
      const r = await fetchUrl("http://network.invalid/partial");
      expect(r.ok).toBe(false); expect(r.complete).toBe(false); expect(r.error).toBeTruthy();
      expect(r.bytes).toBe(6); expect(r.sha256).toBe(H("prefix")); expect(attempts).toBe(3);
    } finally { setGlobalDispatcher(prior); }
  });
  it("C06 TRACE reaches the lower transport instead of the forbidden fetch constructor", async () => {
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    mock.get("http://network.invalid").intercept({ path: "/trace", method: "TRACE" }).reply(200, "TRACE echo");
    try { const r = await fetchUrl("http://network.invalid/trace", { method: "TRACE" }); expect(r.status).toBe(200); expect(r.body).toBe("TRACE echo"); }
    finally { setGlobalDispatcher(prior); await mock.close(); }
  });
  it("F05 custom DNS resolvers own all A/AAAA/CNAME queries without system fallback", async () => {
    const dns = (await import("node:dns")).promises;
    const system = vi.spyOn(dns, "resolve4").mockResolvedValue(["192.0.2.99"]);
    const servers = vi.spyOn(dns.Resolver.prototype, "setServers");
    const a = vi.spyOn(dns.Resolver.prototype, "resolve4").mockResolvedValue(["192.0.2.10"] as any);
    const aaaa = vi.spyOn(dns.Resolver.prototype, "resolve6").mockResolvedValue(["2001:db8::10"] as any);
    const cname = vi.spyOn(dns.Resolver.prototype, "resolveCname").mockResolvedValue(["alias.invalid"]);
    try {
      const { resolveWith } = await import("../src/domain/dnsResolve.js");
      expect(await resolveWith("network.invalid", ["192.0.2.53"])).toMatchObject({ a: ["192.0.2.10"], aaaa: ["2001:db8::10"], cname: ["alias.invalid"] });
      expect(servers).toHaveBeenCalledWith(["192.0.2.53"]); expect(system).not.toHaveBeenCalled();
      expect(a).toHaveBeenCalledTimes(1); expect(aaaa).toHaveBeenCalledTimes(1); expect(cname).toHaveBeenCalledTimes(1);
    } finally { vi.restoreAllMocks(); }
  });
  it("G03 emits immutable transmission receipts but not invalid or pre-aborted requests", async () => {
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    mock.get("http://network.invalid").intercept({ path: "/receipt?q=1" }).reply(200, "actual");
    try { await withExecution({ tool: "network-test", runId: "network-run" }, async () => {
      const r = await fetchUrl("http://network.invalid/receipt?q=1", { cookie: "sid=low" });
      expect(receipts()).toHaveLength(1);
      expect(receipts()[0]).toMatchObject({ url: "http://network.invalid/receipt?q=1", method: "GET", status: 200, responseHash: H("actual"), complete: true, runId: "network-run" });
      expect(receipts()[0]!.requestHash).toMatch(/^[0-9a-f]{64}$/); expect(r.sha256).toBe(H("actual"));
      const c = new AbortController(); c.abort();
      const failed = await fetchUrl("http://network.invalid/unfired", { signal: c.signal });
      expect(failed).toMatchObject({ status: 0, ok: false, complete: false, storedBytes: 0, storedHash: H("") });
      expect(receipts()).toHaveLength(1);
    }); } finally { setGlobalDispatcher(prior); await mock.close(); }
  });
  it("C05 cancelled queue entries never reach transport and network timeout starts after the queue", async () => {
    vi.useFakeTimers(); vi.setSystemTime(200000); setGlobalRateLimit(1);
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    mock.get("http://network.invalid").intercept({ path: "/queue" }).reply(200, "queued").times(2);
    try {
      expect((await fetchUrl("http://network.invalid/queue", { timeoutMs: 50 })).status).toBe(200);
      const c = new AbortController(); const cancelled = fetchUrl("http://network.invalid/unfired", { signal: c.signal }); c.abort();
      const waiting = fetchUrl("http://network.invalid/queue", { timeoutMs: 50 });
      await vi.advanceTimersByTimeAsync(1000);
      expect((await waiting).status).toBe(200); expect((await cancelled).status).toBe(0); mock.assertNoPendingInterceptors();
    } finally { setGlobalRateLimit(0); setGlobalDispatcher(prior); await mock.close(); }
  });
  it("C01 tunnels raw TCP through CONNECT and refuses proxy failures without a direct fallback", async () => {
    const sockets: WireSocket[] = [];
    const connect = vi.spyOn(net, "connect").mockImplementation(((opts: any) => {
      const socket = new WireSocket((b, s) => { if (b.toString().startsWith("CONNECT")) queueMicrotask(() => s.push("HTTP/1.1 200 Connection established\r\n\r\n")); });
      sockets.push(socket); queueMicrotask(() => socket.emit("connect")); return socket;
    }) as any);
    try {
      const { openTunnel } = await import("../src/adapters/rawTunnel.js");
      const socket = await openTunnel({ host: "target.invalid", port: 443, proxy: "http://u:p@proxy.invalid:8080", timeoutMs: 100 });
      expect(connect.mock.calls[0]?.[0]).toMatchObject({ host: "proxy.invalid", port: 8080 });
      expect(sockets[0]!.written[0]!.toString()).toContain("CONNECT target.invalid:443 HTTP/1.1\r\n");
      expect(sockets[0]!.written[0]!.toString()).toContain("Proxy-Authorization: Basic dTpw"); socket.destroy();
      connect.mockImplementation(((opts: any) => {
        const s = new WireSocket((_b, x) => queueMicrotask(() => x.push("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")));
        queueMicrotask(() => s.emit("connect")); return s;
      }) as any);
      await expect(openTunnel({ host: "target.invalid", port: 443, proxy: "http://proxy.invalid:8080", timeoutMs: 100 })).rejects.toThrow(/407/);
      expect(connect).toHaveBeenCalledTimes(2);
    } finally { vi.restoreAllMocks(); }
  });
  it("C07 WS validates the full fragmented handshake and does not call Origin acceptance a vulnerability", async () => {
    const connect = vi.spyOn(net, "connect").mockImplementation((() => {
      const socket = new WireSocket((b, s) => {
        const req = b.toString(); const key = req.match(/Sec-WebSocket-Key: ([^\r]+)/i)?.[1] ?? "";
        const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
        queueMicrotask(() => { s.push("HTTP/1.1 101 Switching Proto"); setImmediate(() => s.push(`cols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`)); });
      }); queueMicrotask(() => socket.emit("connect")); return socket;
    }) as any);
    try {
      const { probeWsOrigin } = await import("../src/domain/wsOrigin.js");
      const { mkdtemp, rm } = await import("node:fs/promises");
      const root = await mkdtemp(`${process.env.TMPDIR}/ws-network-`);
      try { const out = await probeWsOrigin({ url: "ws://network.invalid/ws", outputRoot: root, timeoutMs: 100 });
        expect(out.variants.every(v => v.upgraded && v.status === 101)).toBe(true);
        expect(out.vulnerable).toBe(false); expect(out).toMatchObject({ crossOriginAccepted: true, outcome: "candidate" });
      } finally { await rm(root, { recursive: true, force: true }); }
      expect(connect).toHaveBeenCalledTimes(2);
    } finally { vi.restoreAllMocks(); }
  });
  it("C06 TLS probes pin exact legacy versions and retain certificate policy through the proxy", async () => {
    const direct = vi.spyOn(net, "connect").mockImplementation((() => {
      const s = new WireSocket((b, sock) => { if (b.toString().startsWith("CONNECT")) queueMicrotask(() => sock.push("HTTP/1.1 200 Connected\r\n\r\n")); });
      queueMicrotask(() => s.emit("connect")); return s;
    }) as any);
    const secure = vi.spyOn(tls, "connect").mockImplementation(((opts: any) => {
      const s: any = new WireSocket(() => {}); s.getProtocol = () => opts.maxVersion ?? "TLSv1.3"; s.getCipher = () => ({ name: "fixture-cipher" });
      s.getPeerCertificate = () => ({ subject: { CN: "network.invalid" }, issuer: {}, valid_from: "Jan 1 00:00:00 2020 GMT", valid_to: "Jan 1 00:00:00 2030 GMT" });
      s.authorized = false; s.authorizationError = "SELF_SIGNED_CERT_IN_CHAIN";
      queueMicrotask(() => s.emit("secureConnect")); return s;
    }) as any);
    try {
      const { connectTlsAudit } = await import("../src/domain/tlsAudit.js");
      const out = await connectTlsAudit(new URL("https://network.invalid"), { proxy: "http://proxy.invalid:8080", rejectUnauthorized: false, timeoutMs: 100 });
      expect(out.negotiated?.protocol).toBe("TLSv1.3"); expect(out.weakProtocols).toHaveLength(2);
      const opts = secure.mock.calls.map(c => c[0] as any);
      expect(opts.filter(o => o.maxVersion).map(o => [o.minVersion, o.maxVersion])).toEqual([["TLSv1", "TLSv1"], ["TLSv1.1", "TLSv1.1"]]);
      expect(opts.every(o => o.socket && o.rejectUnauthorized === false)).toBe(true);
      expect(direct.mock.calls.every(c => (c[0] as any).host === "proxy.invalid")).toBe(true);
      expect(out).toMatchObject({ certificatePolicy: "insecure", certificateAuthorized: false });
    } finally { vi.restoreAllMocks(); }
  });
  it("F05 fingerprint audits each structured Set-Cookie and reports skipped PUT distinctly", async () => {
    const prior = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect(); setGlobalDispatcher(mock);
    const pool = mock.get("http://network.invalid");
    pool.intercept({ path: "/", method: "GET" }).reply(200, "base", { headers: { "set-cookie": ["a=1; Secure; HttpOnly; SameSite=Lax", "b=2; Path=/; SameSite=None"] } });
    pool.intercept({ path: "/", method: "OPTIONS" }).reply(200, "", { headers: { allow: "GET, TRACE" } });
    pool.intercept({ path: "/", method: "TRACE" }).reply(200, "x-velric-probe: 1");
    const { mkdtemp, rm } = await import("node:fs/promises"); const root = await mkdtemp(`${process.env.TMPDIR}/fp-network-`);
    try {
      const { fingerprint } = await import("../src/domain/fingerprint.js"); const r = await fingerprint({ baseUrl: "http://network.invalid", outputRoot: root });
      expect(r.cookies).toEqual([{ name: "a", secure: true, httpOnly: true, sameSite: "Lax" }, { name: "b", secure: false, httpOnly: false, sameSite: "None" }]);
      expect(r.methods.traceWorks).toBe(true); expect(r.methods).toMatchObject({ putOutcome: "skipped", traceOutcome: "accepted" });
    } finally { setGlobalDispatcher(prior); await mock.close(); await rm(root, { recursive: true, force: true }); }
  });
  it("C07 raw HTTP retains dot-segment bytes and reads a complete bounded response", async () => {
    const writes: string[] = [];
    vi.spyOn(net, "connect").mockImplementation((() => {
      const s = new WireSocket((b, socket) => { writes.push(b.toString()); queueMicrotask(() => { socket.push("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nab"); setImmediate(() => socket.push("cdefgh")); }); });
      queueMicrotask(() => s.emit("connect")); return s;
    }) as any);
    try {
      const { rawHttpExchange } = await import("../src/adapters/rawTunnel.js");
      const request = "GET /x/../raw?q=1 HTTP/1.1\r\nHost: network.invalid\r\nConnection: close\r\n\r\n";
      const r = await rawHttpExchange("http://network.invalid/x/../raw?q=1", Buffer.from(request), { timeoutMs: 100, maxBytes: 64 });
      expect(writes).toEqual([request]); expect(r).toMatchObject({ status: 200, complete: true, body: "abcdefgh", requestHash: H(request), responseHash: H("abcdefgh") });
    } finally { vi.restoreAllMocks(); }
  });
});
