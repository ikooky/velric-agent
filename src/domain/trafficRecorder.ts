import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { connect as netConnect } from "node:net";
import type { Duplex } from "node:stream";
import { request as undiciRequest, type Dispatcher } from "undici";
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
  private upstreamProxy?: string;
  private maxExchanges: number;
  private upstreamAgent: import("undici").ProxyAgent | null = null;

  constructor(input: TrafficRecorderInput) {
    this.outDir = input.outputRoot;
    this.blobDir = join(input.outputRoot, "blobs");
    this.preferredPort = input.port ?? 0;
    this.upstreamProxy = input.upstreamProxy;
    this.maxExchanges = input.maxExchanges ?? 10000;
  }

  readonly start = async (port?: number): Promise<number> => {
    const listenPort = port ?? this.preferredPort ?? 0;
    await mkdir(this.blobDir, { recursive: true });
    const server = createServer((req, res) => { void this.handleHttp(req, res); });
    server.on("connect", (req, clientSock, head) => { void this.handleConnect(req, clientSock, head); });
    await new Promise<void>((resolve) => server.listen(listenPort, "127.0.0.1", resolve));
    this.server = server;
    const addr = server.address();
    return typeof addr === "object" && addr !== null ? addr.port : listenPort;
  };

  readonly stop = async (): Promise<void> => {
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
    if (this.upstreamAgent) { await this.upstreamAgent.destroy().catch(() => {}); this.upstreamAgent = null; }
  };

  readonly getExchanges = (): readonly RecordedExchange[] => this.exchanges;

  /** Replay: fetch stored full bodies for one exchange (HTTP-captured only). */
  async exchangeBodies(id: string): Promise<{ request?: Buffer; response?: Buffer } | null> {
    const rec = this.exchanges.find((e) => e.id === id);
    if (!rec || !rec.reqBodyHash) return null;
    const load = async (hash: string | null): Promise<Buffer | undefined> => {
      if (!hash) return undefined;
      try { return await import("node:fs/promises").then((fs) => fs.readFile(join(this.blobDir, hash.slice(0, 2), hash + ".bin"))); }
      catch { return undefined; }
    };
    return { request: await load(rec.reqBodyHash), response: await load(rec.respBodyHash) };
  };

  private readonly spill = async (body: Buffer): Promise<string> => {
    const hash = createHash("sha256").update(body).digest("hex");
    const dir = join(this.blobDir, hash.slice(0, 2));
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, hash + ".bin"), body);
    return hash;
  };

  private readonly record = async (rec: RecordedExchange): Promise<void> => {
    this.exchanges.push(rec);
    await appendFile(join(this.outDir, "traffic.ndjson"), JSON.stringify(rec) + "\n").catch(() => {});
  };

  private readonly handleHttp = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const id = `x${++this.counter}`;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    const bodyPromise = new Promise<Buffer>((resolve) => req.on("end", () => resolve(Buffer.concat(chunks))));
    const body = await bodyPromise;

    if (this.exchanges.length >= this.maxExchanges) { res.writeHead(503); res.end("recorder cap"); return; }
    const reqHash = body.length > 0 ? await this.spill(body) : null;

    try {
      // One shared upstream agent for the recorder's lifetime (pooled sockets,
      // destroyed in stop()) — not one per request.
      if (this.upstreamProxy && !this.upstreamAgent) {
        const { ProxyAgent } = await import("undici");
        this.upstreamAgent = new ProxyAgent({ uri: this.upstreamProxy });
      }
      const dispatcher: Dispatcher | undefined = this.upstreamAgent ?? undefined;
      const r = await undiciRequest(String(req.url), {
        method: String(req.method ?? "GET"),
        headers: { ...omit(req.headers, ["host", "proxy-connection"]) as Record<string, string> },
        body: body.length > 0 ? body : undefined,
        dispatcher,
      });
      const respBody = Buffer.from(await r.body.arrayBuffer());
      const respHash = respBody.length > 0 ? await this.spill(respBody) : null;
      const respHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(r.headers)) respHeaders[k] = Array.isArray(v) ? v.join(", ") : String(v);
      await this.record({
        ts: new Date().toISOString(), id, method: String(req.method ?? "GET"), url: String(req.url),
        status: Number(r.statusCode ?? 0), reqHeaders: flattenHeaders(req.headers), reqBodyHash: reqHash, reqBodyBytes: body.length,
        respHeaders, respBodyHash: respHash, respBodyBytes: respBody.length, via: "http-capture",
      });
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
      void this.record({
        ts: new Date().toISOString(), id, method: "CONNECT", url: raw,
        status, reqHeaders: flattenHeaders(req.headers), reqBodyHash: null, reqBodyBytes: upBytes,
        respHeaders: null, respBodyHash: null, respBodyBytes: downBytes, via: "https-tunnel",
      });
    };
    clientSock.on("data", (d: Buffer) => { upBytes += d.length; });

    const srvSock = netConnect({ host, port });
    srvSock.on("data", (d: Buffer) => { downBytes += d.length; });
    srvSock.on("connect", () => {
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
