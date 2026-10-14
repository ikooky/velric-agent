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
  private upstreamProxy?: string;
  private maxExchanges: number;

  constructor(input: TrafficRecorderInput) {
    this.outDir = input.outputRoot;
    this.blobDir = join(input.outputRoot, "blobs");
    this.upstreamProxy = input.upstreamProxy;
    this.maxExchanges = input.maxExchanges ?? 10000;
  }

  readonly start = async (port = 8788): Promise<number> => {
    await mkdir(this.blobDir, { recursive: true });
    const server = createServer((req, res) => { void this.handleHttp(req, res); });
    server.on("connect", (req, clientSock, head) => { void this.handleConnect(req, clientSock, head); });
    await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
    this.server = server;
    const addr = server.address();
    return typeof addr === "object" && addr !== null ? addr.port : port;
  };

  readonly stop = async (): Promise<void> => {
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
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
      const dispatcher: Dispatcher | undefined = this.upstreamProxy
        ? new (await import("undici")).ProxyAgent({ uri: this.upstreamProxy })
        : undefined;
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
    const [host, portStr] = (req.url ?? "").split(":");
    const port = Number(portStr) || 443;
    const srvSock = netConnect({ host: host!, port }, () => {
      clientSock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) srvSock.write(head);
      clientSock.pipe(srvSock).pipe(clientSock);
    });
    let upBytes = 0;
    let downBytes = 0;
    clientSock.on("data", (d: Buffer) => { upBytes += d.length; });
    srvSock.on("data", (d: Buffer) => { downBytes += d.length; });
    const done = (): void => {
      void this.record({
        ts: new Date().toISOString(), id, method: "CONNECT", url: String(req.url),
        status: 200, reqHeaders: flattenHeaders(req.headers), reqBodyHash: null, reqBodyBytes: upBytes,
        respHeaders: null, respBodyHash: null, respBodyBytes: downBytes, via: "https-tunnel",
      });
      try { clientSock.destroy(); srvSock.destroy(); } catch { /* gone */ }
    };
    clientSock.on("close", done);
    srvSock.on("close", done);
    clientSock.on("error", () => {});
    srvSock.on("error", () => {});
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
