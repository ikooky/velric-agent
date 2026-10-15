import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect, TLSSocket } from "node:tls";
import { createServer as createHttpServer } from "node:http";
import type { Duplex } from "node:stream";
import { request as undiciRequest, Agent, type Dispatcher } from "undici";
import { mkdir, writeFile, appendFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

/** Traffic recording proxy (velric platform layer, deterministic port):
 *  a forward HTTP/HTTPS proxy that records every exchange (request line +
 *  headers + body, response status + headers + body hash/spill) into an
 *  append-only NDJSON log + blob store — no mitmproxy/CA dependency.
 *
 *  HTTPS: CONNECT tunneling records metadata + sizes only (TLS passthrough);
 *  HTTP: full request/response capture. Clients can opt into TLS MITM via
 *  env (skip — deterministic scope). */

export interface TrafficRecorderInput {
  readonly outputRoot: string;
  /** Preferred listen port; 0 = ephemeral. */
  readonly port?: number;
  readonly upstreamProxy?: string;
  /** Stop after this many exchanges (safety cap). */
  readonly maxExchanges?: number;
  /** Decrypt HTTPS via the in-process CA (record full exchanges instead of
   *  tunnel metadata). Clients must trust mitm-ca.cert.pem. */
  readonly mitm?: boolean;
}

export interface RecordedExchange {
  readonly ts: string;
  readonly id: string;
  readonly method: string;
  readonly url: string;
  readonly status: number | null;
  readonly reqHeaders: Record<string, string>;
  readonly reqBodyHash: string | null;
  readonly reqBodyBytes: number;
  readonly respHeaders: Record<string, string> | null;
  readonly respBodyHash: string | null;
  readonly respBodyBytes: number;
  readonly via: "http-capture" | "https-tunnel";
}

export class TrafficRecorder {
  private readonly exchanges: RecordedExchange[] = [];
  private server: Server | null = null;
  private counter = 0;
  private readonly blobDir: string;
  private readonly outDir: string;
  private readonly preferredPort: number;
  private mitmEnabled: boolean;
  private mitmCA: import("./mitm.js").MitmCA | null = null;
  private plainServer: import("node:http").Server | null = null;
  private upstreamProxy?: string;
  private maxExchanges: number;
  private upstreamAgent: import("undici").ProxyAgent | null = null;
  private relaxAgent: Agent | null = null;
  private readonly tunnels = new Set<{ c: import("node:stream").Duplex; s: import("node:net").Socket }>();

  constructor(input: TrafficRecorderInput) {
    this.outDir = input.outputRoot;
    this.blobDir = join(input.outputRoot, "blobs");
    this.preferredPort = input.port ?? 0;
    this.upstreamProxy = input.upstreamProxy;
    this.mitmEnabled = input.mitm ?? false;
    this.maxExchanges = input.maxExchanges ?? 10000;
  }

  readonly start = async (port?: number): Promise<number> => {
    const listenPort = port ?? this.preferredPort ?? 0;
    await mkdir(this.blobDir, { recursive: true });
    if (this.mitmEnabled) {
      const { createOrLoadCA } = await import("./mitm.js");
      this.mitmCA = await createOrLoadCA(this.outDir);
      // Internal cleartext HTTP hop: decrypted requests are fed here and
      // re-dispatched through the same handleHttp recording path.
      this.plainServer = createHttpServer((req, res) => { void this.handleHttp(req, res); });
      await new Promise<void>((resolve) => this.plainServer!.listen(0, "127.0.0.1", resolve));
    }
    const server = createServer((req, res) => { void this.handleHttp(req, res); });
    server.on("connect", (req, clientSock, head) => { void this.handleConnect(req, clientSock, head); });
    await new Promise<void>((resolve) => server.listen(listenPort, "127.0.0.1", resolve));
    this.server = server;
    const addr = server.address();
    return typeof addr === "object" && addr !== null ? addr.port : listenPort;
  };

  readonly stop = async (): Promise<void> => {
    if (this.server) {
      // close() waits on open sockets — destroy live tunnels first, then
      // sweep keep-alive connections (Node >= 18.2).
      for (const t of this.tunnels) { try { t.c.destroy(); } catch { /* gone */ } try { t.s.destroy(); } catch { /* gone */ } }
      this.tunnels.clear();
      this.server.closeAllConnections?.();
      await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    }
    this.server = null;
    if (this.plainServer) { this.plainServer.closeAllConnections?.(); await new Promise<void>((r) => this.plainServer!.close(() => r())); this.plainServer = null; }
    if (this.upstreamAgent) { await this.upstreamAgent.destroy().catch(() => {}); this.upstreamAgent = null; }
    if (this.relaxAgent) { await this.relaxAgent.destroy().catch(() => {}); this.relaxAgent = null; }
  };

  readonly getExchanges = (): readonly RecordedExchange[] => this.exchanges;

  /** Replay: fetch stored full bodies for one exchange (HTTP-captured only). */
  async exchangeBodies(id: string): Promise<{ request?: Buffer; response?: Buffer } | null> {
    const rec = this.exchanges.find((e) => e.id === id);
    if (!rec) return null;
    const load = async (hash: string | null): Promise<Buffer | undefined> => {
      if (!hash) return undefined;
      try { return await import("node:fs/promises").then((fs) => fs.readFile(join(this.blobDir, hash.slice(0, 2), hash + ".bin"))); }
      catch { return undefined; }
    };
    // reqBodyHash is null for body-less requests (GET/CONNECT) — that must
    // not block reading the RESPONSE body.
    return { request: rec.reqBodyHash ? await load(rec.reqBodyHash) : undefined, response: await load(rec.respBodyHash) };
  };

  private readonly spill = async (body: Buffer): Promise<string> => {
    const hash = createHash("sha256").update(body).digest("hex");
    const dir = join(this.blobDir, hash.slice(0, 2));
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, hash + ".bin"), body);
    return hash;
  };

  private readonly record = async (rec: RecordedExchange): Promise<void> => {
    // The cap applies to EVERY recording path (handleHttp previously
    // enforced it, but CONNECT finish() and recordLogOnly pushed unbounded).
    if (this.exchanges.length >= this.maxExchanges) return;
    this.exchanges.push(rec);
    await appendFile(join(this.outDir, "traffic.ndjson"), JSON.stringify(rec) + "\n").catch(() => {});
  };

  private readonly handleHttp = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const id = `x${++this.counter}`;
    const MAX_BODY = 32 * 1024 * 1024; // one-body cap: maxExchanges bounds count, not size
    const chunks: Buffer[] = [];
    let reqBytes = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      reqBytes += c.length;
      if (reqBytes <= MAX_BODY) chunks.push(c);
      else tooBig = true;
    });
    const bodyPromise = new Promise<Buffer>((resolve, reject) => {
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("aborted", () => resolve(Buffer.concat(chunks))); // client aborted: record what we have
      req.on("error", (e) => reject(e));
    });
    let body: Buffer;
    try { body = await bodyPromise; } catch (e) { res.writeHead(400); res.end(String((e as Error).message)); return; }
    if (tooBig) { res.writeHead(413); res.end("body too large"); return; }

    if (this.exchanges.length >= this.maxExchanges) { res.writeHead(503); res.end("recorder cap"); return; }
    const reqHash = body.length > 0 ? await this.spill(body) : null;

    try {
      // One shared upstream agent for the recorder's lifetime (pooled sockets,
      // destroyed in stop()) — not one per request.
      if (this.upstreamProxy && !this.upstreamAgent) {
        const { ProxyAgent } = await import("undici");
        // Same recon TLS posture through the upstream proxy as direct: a
        // ProxyAgent built on a relaxed connect option (previously the
        // proxied path validated certs the direct path did not — inverted
        // posture between the two branches).
        const agent = new ProxyAgent({ uri: this.upstreamProxy, requestTls: { rejectUnauthorized: false } });
        // Init race guard: two concurrent first requests can both pass the
        // !upstreamAgent check; the loser's agent would be overwritten and
        // never destroyed (pooled socket leak). Keep the winner, destroy the
        // loser immediately.
        if (this.upstreamAgent) await agent.destroy().catch(() => undefined);
        else this.upstreamAgent = agent;
      }
      // One shared relaxed Agent for direct fetches — created once, pooled,
      // destroyed in stop(). Recon posture: operator-authorized targets,
      // frequently self-signed/internal, mirror fetchUrl's TLS posture.
      if (!this.relaxAgent) this.relaxAgent = new Agent({ connect: { rejectUnauthorized: false } });
      const r = await undiciRequest(String(req.url), {
        method: String(req.method ?? "GET"),
        headers: { ...omit(req.headers, ["host", "proxy-connection"]) as Record<string, string> },
        body: body.length > 0 ? body : undefined,
        dispatcher: this.upstreamAgent ?? this.relaxAgent,
      });
      // Cap the buffered upstream body: stream-read with a running counter,
      // keep the prefix up to the cap.
      const respChunks: Buffer[] = [];
      let respLen = 0;
      for await (const c of r.body as unknown as AsyncIterable<Buffer>) {
        respLen += c.length;
        if (respLen > MAX_BODY) break;
        respChunks.push(c);
      }
      const respBody = Buffer.concat(respChunks);
      void respLen;
      const respHash = respBody.length > 0 ? await this.spill(respBody) : null;
      const respHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(r.headers)) respHeaders[k] = Array.isArray(v) ? v.join(", ") : String(v);
      await this.record({
        ts: new Date().toISOString(), id, method: String(req.method ?? "GET"), url: String(req.url),
        status: Number(r.statusCode ?? 0), reqHeaders: flattenHeaders(req.headers), reqBodyHash: reqHash, reqBodyBytes: body.length,
        respHeaders, respBodyHash: respHash, respBodyBytes: respBody.length, via: "http-capture",
      });
      // If the upstream body was truncated at MAX_BODY, the passthrough
      // content-length must describe what we actually send, not what the
      // origin claimed — otherwise the client waits for missing bytes.
      const cl2 = Number(respHeaders["content-length"] ?? NaN);
      if (respBody.length < cl2) { respHeaders["content-length"] = String(respBody.length); }
      res.writeHead(r.statusCode, respHeaders);
      res.end(respBody);
    } catch (e) {
      await this.record({
        ts: new Date().toISOString(), id, method: String(req.method ?? "GET"), url: String(req.url),
        status: null as number | null, reqHeaders: flattenHeaders(req.headers), reqBodyHash: reqHash, reqBodyBytes: body.length,
        respHeaders: null, respBodyHash: null, respBodyBytes: 0, via: "http-capture",
      });
      res.writeHead(502); res.end("upstream error");
    }
  };

  /** Replay one decrypted request into the internal HTTP hop for recording.
   *  The hop is a proxy-form server: the request line carries the ABSOLUTE
   *  target URL, exactly like a forward-proxy request. Raw socket because
   *  undici request() cannot express absolute-form targets. */
  private readonly mirrorToHop = (host: string, hopPort: number, reqBytes: Buffer): void => {
    try {
      const firstLine = reqBytes.toString("latin1").split("\r\n")[0] ?? "";
      const method = firstLine.split(" ")[0] ?? "GET";
      const rawTarget = firstLine.split(" ")[1] ?? "/";
      const target = /^https?:\/\//.test(rawTarget) ? rawTarget : `https://${host}${rawTarget}`;
      // Non-idempotent methods are NEVER replayed to the hop (the hop would
      // re-issue the request upstream — a state-changing double POST). They
      // are recorded log-only via recordLogOnly below.
      const IDEMPOTENT = new Set(["GET", "HEAD", "OPTIONS"]);
      if (!IDEMPOTENT.has(method.toUpperCase())) {
        void this.recordLogOnly(host, reqBytes);
        return;
      }
      const headerEnd = reqBytes.indexOf("\r\n\r\n");
      const headerBlock = reqBytes.subarray(0, headerEnd).toString("latin1");
      // Replace the origin-form target with the absolute one, drop hop-irrelevant headers.
      const lines = headerBlock.split("\r\n");
      lines[0] = `${method} ${target} HTTP/1.1`;
      const kept = lines.filter((l) => !/^proxy-connection:/i.test(l));
      const out = Buffer.from(kept.join("\r\n") + "\r\n\r\n", "latin1");
      const payload = reqBytes.subarray(headerEnd + 4);
      const sock = netConnect({ host: "127.0.0.1", port: hopPort }, () => {
        sock.write(Buffer.concat([out, payload]));
      });
      const drain: Buffer[] = [];
      sock.on("data", (d: Buffer) => { drain.push(d); if (drain.length > 64) sock.destroy(); });
      sock.on("error", () => { /* best effort */ });
      const kill = setTimeout(() => sock.destroy(), 10000);
      sock.on("close", () => clearTimeout(kill));
    } catch { /* mirror is best-effort recording */ }
  };

  /** Log-only recording for non-idempotent decrypted requests: the exchange
   *  lands in traffic.ndjson (+ req body blob) without any upstream replay. */
  private readonly recordLogOnly = async (host: string, reqBytes: Buffer): Promise<void> => {
    try {
      const headerEnd = reqBytes.indexOf("\r\n\r\n");
      const headerBlock = reqBytes.subarray(0, headerEnd < 0 ? reqBytes.length : headerEnd).toString("latin1");
      const lines = headerBlock.split("\r\n");
      const [method, rawTarget] = (lines[0] ?? "GET / HTTP/1.1").split(" ");
      const headers: Record<string, string> = {};
      for (const l of lines.slice(1)) {
        const idx = l.indexOf(":");
        if (idx > 0) headers[l.slice(0, idx).trim().toLowerCase()] = l.slice(idx + 1).trim();
      }
      const body = headerEnd >= 0 ? reqBytes.subarray(headerEnd + 4) : Buffer.alloc(0);
      const target = /^https?:\/\//.test(rawTarget ?? "") ? rawTarget! : `https://${host}${rawTarget ?? "/"}`;
      const reqHash = body.length > 0 ? await this.spill(body) : null;
      await this.record({
        ts: new Date().toISOString(), id: `x${++this.counter}`, method: method ?? "POST", url: target,
        status: null, reqHeaders: headers, reqBodyHash: reqHash, reqBodyBytes: body.length,
        respHeaders: null, respBodyHash: null, respBodyBytes: 0, via: "http-capture",
      });
    } catch { /* log-only best effort */ }
  };

  private readonly handleConnect = (req: IncomingMessage, clientSock: Duplex, head: Buffer): void => {
    const id = `x${++this.counter}`;
    // IPv6-safe host:port split — bracket form [::1]:443, bare ::1:443, host:443
    const raw = String(req.url ?? "");
    const v6 = raw.startsWith("[") ? raw.match(/^\[([^\]]+)\](?::(\d+))?$/) : null;
    const host = v6 ? v6[1]! : raw.slice(0, raw.lastIndexOf(":")) || raw;
    const port = Number(v6 ? v6[2] : raw.slice(raw.lastIndexOf(":") + 1)) || 443;

    let upBytes = 0;
    let downBytes = 0;
    let settled = false;
    const finish = (status: number | null): void => {
      if (settled) return; // exactly one record per tunnel — close fires on both ends
      settled = true;
      clearTimeout(idle);
      this.tunnels.delete(tunnel);
      void this.record({
        ts: new Date().toISOString(), id, method: "CONNECT", url: raw,
        status, reqHeaders: flattenHeaders(req.headers), reqBodyHash: null, reqBodyBytes: upBytes,
        respHeaders: null, respBodyHash: null, respBodyBytes: downBytes, via: "https-tunnel",
      });
    };
    clientSock.on("data", (d: Buffer) => { upBytes += d.length; });

    const srvSock = netConnect({ host, port });
    const tunnel = { c: clientSock, s: srvSock };
    this.tunnels.add(tunnel);
    // Idle timeout: a silent tunnel must not hold a socket pair open forever.
    const idle = setTimeout(() => { finish(null); try { clientSock.destroy(); srvSock.destroy(); } catch { /* gone */ } }, 300000);
    const bump = (): void => { idle.refresh(); };
    clientSock.on("data", bump);
    srvSock.on("data", bump);
    srvSock.on("data", (d: Buffer) => { downBytes += d.length; });
    srvSock.on("connect", () => {
      // MITM mode: terminate TLS locally instead of piping bytes through.
      // The client sees a leaf cert signed by our CA; decrypted plaintext
      // HTTP flows through the internal hop, gets recorded fully, and is
      // re-encrypted toward the real server.
      if (this.mitmCA && this.plainServer) {
        // The raw upstream socket is NOT used in MITM mode (the TLS pair
        // below carries the traffic) — destroy it instead of leaking a live
        // TCP connection to the origin. Remove its close/error listeners
        // first: their finish(200)+destroy(clientSock) would kill the
        // client right after the CONNECT 200 is written.
        srvSock.removeAllListeners("close");
        srvSock.removeAllListeners("error");
        srvSock.destroy();
        this.tunnels.delete(tunnel);
        // Server side: present the forged leaf to the CLIENT on this socket.
        const leaf = this.mitmCA.sign(host);
        const hopAddr = this.plainServer!.address();
        const hopPort = typeof hopAddr === "object" && hopAddr !== null ? hopAddr.port : 0;
        clientSock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const clientTls = new TLSSocket(clientSock, { isServer: true, key: leaf.keyPem, cert: leaf.certPem, rejectUnauthorized: false });
        // Client side: real TLS toward the ORIGIN server.
        // servername must be a DNS name — IP targets omit it (Node rejects IP SNI).
        const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
        const originTls = tlsConnect({ host, port, rejectUnauthorized: false, ...(isIp ? {} : { servername: host }) });
        const tlsPair = { c: clientTls, s: originTls as unknown as import("node:net").Socket };
        this.tunnels.add(tlsPair);
        // Tunnel set must shrink when the pair dies, or every MITM connection
        // leaks a dead socket pair until stop() (getTunnels() grows unbounded).
        const reapPair = (): void => { this.tunnels.delete(tlsPair); };
        clientTls.on("close", reapPair);
        originTls.on("close", reapPair);
        // Recording hop: decrypted client requests are replayed (absolute-
        // form) into the internal HTTP server, which records the exchange
        // and fetches the real response via its own upstream path; its
        // response is NOT looped back (originTls already serves the client).
        if (hopPort <= 0) { finish(null); try { clientTls.destroy(); originTls.destroy(); } catch { /* gone */ } return; }
        let mirrorBuf = Buffer.alloc(0);
        const MIRROR_BUF_CAP = 8 * 1024 * 1024; // chunked/bodied request stream cap
        clientTls.on("data", (d: Buffer) => {
          upBytes += d.length;
          bump();
          originTls.write(d);
          // Best-effort mirror: accumulate plaintext, split on complete
          // HTTP/1.1 requests, forward each to the recording hop once.
          mirrorBuf = Buffer.concat([mirrorBuf, d]);
          for (;;) {
            if (mirrorBuf.length > MIRROR_BUF_CAP) { mirrorBuf = Buffer.alloc(0); break; } // oversized stream: drop mirroring, keep proxying
            const headerEnd = mirrorBuf.indexOf("\r\n\r\n");
            if (headerEnd < 0) break;
            const headTxt = mirrorBuf.subarray(0, headerEnd).toString("latin1");
            const cl = Number((headTxt.match(/content-length:\s*(\d+)/i) ?? [])[1] ?? 0);
            const chunked = /transfer-encoding:\s*chunked/i.test(headTxt);
            if (chunked) {
              // Chunked framing: mirror only headers when no body, else wait for the
              // terminating 0\r\n\r\n frame; unbounded chunked bodies fall back to
              // header-only mirroring (hop records the exchange with empty body).
              // Standard terminator is "\r\n0\r\n\r\n" (last-chunk CRLF);
              // a bare leading "0\r\n\r\n" occurs on body-less chunked. Slice
              // at the ACTUAL end of the matched terminator — a fixed +7
              // over-consumes 2 bytes when the CRLF prefix is present and
              // permanently skews the mirror stream.
              const bare = mirrorBuf.indexOf("0\r\n\r\n");
              const crlfTerm = mirrorBuf.indexOf("\r\n0\r\n\r\n");
              let anyTerm = -1;
              let termEnd = -1;
              if (crlfTerm >= 0 && (bare < 0 || crlfTerm + 2 <= bare)) { anyTerm = crlfTerm; termEnd = crlfTerm + 7; }
              else if (bare >= 0) { anyTerm = bare; termEnd = bare + 5; }
              if (anyTerm < 0) break;
              const reqBytes = mirrorBuf.subarray(0, termEnd);
              mirrorBuf = mirrorBuf.subarray(termEnd);
              this.mirrorToHop(`${host}:${port}`, hopPort, reqBytes);
              continue;
            }
            const total = headerEnd + 4 + cl;
            if (mirrorBuf.length < total) break;
            const reqBytes = mirrorBuf.subarray(0, total);
            mirrorBuf = mirrorBuf.subarray(total);
            this.mirrorToHop(`${host}:${port}`, hopPort, reqBytes);
          }
        });
        originTls.on("data", (d: Buffer) => { downBytes += d.length; bump(); clientTls.write(d); });
        clientTls.on("end", () => originTls.end());
        originTls.on("end", () => clientTls.end());
        // TLS errors/aborts finish(null); clean close on BOTH ends is a full
        // session — record 200 only when neither side errored (tracked via
        // errored flag; close also fires after error, so guard on it).
        let tlsErrored = false;
        clientTls.on("error", () => { tlsErrored = true; finish(null); try { originTls.destroy(); } catch { /* gone */ } });
        originTls.on("error", () => { tlsErrored = true; finish(null); try { clientTls.destroy(); } catch { /* gone */ } });
        clientTls.on("close", () => { finish(tlsErrored ? null : 200); try { originTls.destroy(); } catch { /* gone */ } });
        originTls.on("close", () => { finish(tlsErrored ? null : 200); try { clientTls.destroy(); } catch { /* gone */ } });
        // Record via the decrypted stream: mirror plaintext into the
        // internal HTTP hop (absolute-form preserved so handleHttp can
        // forward it upstream).
        return;
      }
      clientSock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) srvSock.write(head);
      clientSock.pipe(srvSock).pipe(clientSock);
    });
    clientSock.on("close", () => { finish(200); try { srvSock.destroy(); } catch { /* gone */ } });
    srvSock.on("close", () => { finish(200); try { clientSock.destroy(); } catch { /* gone */ } });
    clientSock.on("error", () => { finish(null); try { srvSock.destroy(); } catch { /* gone */ } });
    srvSock.on("error", () => { finish(502); try { clientSock.destroy(); } catch { /* gone */ } });
  };
}

const flattenHeaders = (h: import("node:http").IncomingHttpHeaders): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
  return out;
};

const omit = (h: import("node:http").IncomingHttpHeaders, keys: string[]): import("node:http").IncomingHttpHeaders => {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(h)) if (!keys.includes(k)) out[k] = v;
  return out as import("node:http").IncomingHttpHeaders;
};

// ---------------- query layer over recorded traffic ----------------

/** Search/query the NDJSON traffic log: host filter, status filter, method
 *  filter, free-text substring over url, paginated — the deterministic
 *  equivalent of velric's SQLite+FTS traffic search. */
export const searchTraffic = async (input: {
  outputRoot: string;
  host?: string;
  status?: number;
  method?: string;
  text?: string;
  page?: number;
  pageSize?: number;
}): Promise<{ total: number; page: number; exchanges: RecordedExchange[] }> => {
  const { readFile } = await import("node:fs/promises");
  let lines: string[] = [];
  try { lines = (await readFile(join(input.outputRoot, "traffic.ndjson"), "utf8")).split("\n").filter(Boolean); }
  catch { return { total: 0, page: 1, exchanges: [] }; }
  let all: RecordedExchange[] = [];
  for (const l of lines) {
    try { all.push(JSON.parse(l) as RecordedExchange); } catch { /* torn tail line */ }
  }
  // CONNECT records store "host:443" (no scheme) — a bare new URL() throws
  // and kills the whole query; skip unparseable rows instead.
  if (input.host) all = all.filter((e) => {
    try { return new URL(e.url.startsWith("https://") || e.url.startsWith("http://") || e.url.includes("://") ? e.url : `https://${e.url}`).hostname === input.host; }
    catch { return false; }
  });
  if (input.status != null) all = all.filter((e) => e.status === input.status);
  if (input.method) all = all.filter((e) => e.method.toUpperCase() === input.method!.toUpperCase());
  if (input.text) all = all.filter((e) => e.url.includes(input.text!));
  const pageSize = input.pageSize ?? 50;
  const page = input.page ?? 1;
  return {
    total: all.length,
    page,
    exchanges: all.slice((page - 1) * pageSize, page * pageSize),
  };
};

/** Fetch one exchange's stored bodies by id (from traffic.ndjson + blobs). */
export const getTraffic = async (input: { outputRoot: string; id: string }): Promise<{ exchange: RecordedExchange | null; bodies: { request?: Buffer; response?: Buffer } | null }> => {
  const { readFile } = await import("node:fs/promises");
  let lines: string[] = [];
  try { lines = (await readFile(join(input.outputRoot, "traffic.ndjson"), "utf8")).split("\n").filter(Boolean); }
  catch { return { exchange: null, bodies: null }; }
  for (const l of lines) {
    let e: RecordedExchange;
    try { e = JSON.parse(l) as RecordedExchange; } catch { continue; }
    if (e.id !== input.id) continue;
    const bodies: { request?: Buffer; response?: Buffer } = {};
    const load = async (hash: string | null): Promise<Buffer | undefined> => {
      if (!hash) return undefined;
      try { return await readFile(join(input.outputRoot, "blobs", hash.slice(0, 2), hash + ".bin")); }
      catch { return undefined; }
    };
    bodies.request = await load(e.reqBodyHash);
    bodies.response = await load(e.respBodyHash);
    return { exchange: e, bodies };
  }
  return { exchange: null, bodies: null };
};
