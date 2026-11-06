import net from "node:net";
import tls, { type SecureVersion } from "node:tls";
import type { Socket } from "node:net";
import { executionSignal, executionRunId, recordReceipt } from "../core/execution.js";
import { createHash } from "node:crypto";
import { principalHash } from "../core/credentials.js";
import { getProxyPool, type ProxyPool } from "../domain/proxyPool.js";

export interface TunnelOptions {
  host: string; port: number; proxy?: string; proxyPool?: ProxyPool; secure?: boolean;
  servername?: string; timeoutMs?: number; signal?: AbortSignal;
  rejectUnauthorized?: boolean; proxyRejectUnauthorized?: boolean;
  minVersion?: SecureVersion; maxVersion?: SecureVersion;
}
const aborted = (): Error => Object.assign(new Error("connection cancelled"), { name: "AbortError" });
const waitReady = (s: Socket, event: "connect" | "secureConnect", timeout: number, signal?: AbortSignal): Promise<Socket> => new Promise((resolve, reject) => {
  const cleanup = (): void => { clearTimeout(timer); s.removeListener(event, ready); s.removeListener("error", fail); s.removeListener("close", closed); signal?.removeEventListener("abort", abort); };
  const fail = (e: Error): void => { cleanup(); s.destroy(); reject(e); };
  const closed = (): void => fail(new Error("connection closed before ready"));
  const abort = (): void => fail(aborted());
  const ready = (): void => { cleanup(); resolve(s); };
  const timer = setTimeout(() => fail(new Error("connect timeout")), timeout);
  s.once(event, ready); s.once("error", fail); s.once("close", closed); signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
});
/** Read a bounded prefix. Any bytes beyond the delimiter remain on the socket. */
export const readSocket = (s: Socket, finished: (b: Buffer) => number, timeoutMs: number, maxBytes: number, signal?: AbortSignal): Promise<Buffer> => new Promise((resolve, reject) => {
  let data = Buffer.alloc(0);
  const cleanup = (): void => { clearTimeout(timer); s.removeListener("data", onData); s.removeListener("end", ended); s.removeListener("close", ended); s.removeListener("error", fail); signal?.removeEventListener("abort", abort); s.pause(); };
  const fail = (e: Error): void => { cleanup(); reject(e); };
  const ended = (): void => fail(new Error("incomplete response"));
  const abort = (): void => fail(aborted());
  const onData = (b: Buffer): void => {
    data = Buffer.concat([data, b]);
    // Size limit wins over a matching terminator: a "complete" header that
    // exceeds the bound is refused, not accepted.
    if (data.length > maxBytes) { cleanup(); fail(new Error("response header limit")); return; }
    let length: number;
    try {
      length = finished(data);
    } catch (e) {
      // finished() throws synchronously inside this 'data' handler (e.g. a
      // malformed SOCKS5 reply) — route it through fail() instead of letting
      // it escape the EventEmitter and kill the process.
      fail(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    if (length >= 0) { cleanup(); if (length < data.length) s.unshift(data.subarray(length)); resolve(data.subarray(0, length)); }
  };
  const timer = setTimeout(() => fail(new Error("read timeout")), timeoutMs);
  s.on("data", onData); s.once("end", ended); s.once("close", ended); s.once("error", fail); signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort(); else s.resume();
});
const untilHeader = (b: Buffer): number => { const i = b.indexOf("\r\n\r\n"); return i < 0 ? -1 : i + 4; };
const socksTunnel = async (s: Socket, u: URL, o: TunnelOptions, timeout: number, signal?: AbortSignal): Promise<void> => {
  const auth = Boolean(u.username || u.password);
  let p = readSocket(s, b => b.length >= 2 ? 2 : -1, timeout, 512, signal); s.write(auth ? Buffer.from([5, 2, 0, 2]) : Buffer.from([5, 1, 0]));
  const hello = await p;
  if (hello[0] !== 5 || ![0, 2].includes(hello[1]!)) throw new Error("SOCKS5 authentication refused");
  if (hello[1] === 2) {
    const user = Buffer.from(decodeURIComponent(u.username)); const pass = Buffer.from(decodeURIComponent(u.password));
    if (!auth || user.length > 255 || pass.length > 255) throw new Error("SOCKS5 credentials invalid");
    p = readSocket(s, b => b.length >= 2 ? 2 : -1, timeout, 512, signal);
    s.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    const response = await p; if (response[1] !== 0) throw new Error("SOCKS5 authentication failed");
  }
  const host = Buffer.from(o.host); if (host.length > 255) throw new Error("SOCKS5 hostname too long");
  const port = Buffer.alloc(2); port.writeUInt16BE(o.port);
  p = readSocket(s, b => {
    if (b.length < 5) return -1;
    const n = b[3] === 1 ? 10 : b[3] === 4 ? 22 : b[3] === 3 ? 7 + b[4]! : 0;
    if (!n) throw new Error("SOCKS5 malformed address"); return b.length >= n ? n : -1;
  }, timeout, 512, signal);
  s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, host.length]), host, port]));
  const reply = await p; if (reply[0] !== 5 || reply[1] !== 0) throw new Error(`SOCKS5 connect refused (${reply[1]})`);
};
/** HTTP CONNECT / SOCKS5 are authoritative. Never retry by connecting to target directly. */
export const openTunnel = async (o: TunnelOptions): Promise<Socket> => {
  const signal = o.signal ?? executionSignal(); if (signal?.aborted) throw aborted();
  if (!o.host || /[\r\n\s]/.test(o.host) || !Number.isInteger(o.port) || o.port < 1 || o.port > 65535) throw new Error("invalid target endpoint");
  const pool = o.proxy ? undefined : o.proxyPool ?? getProxyPool();
  const proxy = o.proxy ?? pool?.next() ?? undefined;
  if (pool && !proxy) throw new Error("proxy pool exhausted");
  const timeout = o.timeoutMs ?? 8000; let socket: Socket | undefined;
  try {
    if (proxy) {
      const u = new URL(proxy); if (!["http:", "https:", "socks5:", "socks:"].includes(u.protocol)) throw new Error("unsupported proxy protocol");
      const host = u.hostname.replace(/^\[|\]$/g, "");
      socket = u.protocol === "https:" ? tls.connect({ host, port: Number(u.port) || 443, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: o.proxyRejectUnauthorized ?? true }) : net.connect({ host, port: Number(u.port) || (u.protocol.startsWith("socks") ? 1080 : 80) });
      await waitReady(socket, u.protocol === "https:" ? "secureConnect" : "connect", timeout, signal);
      if (u.protocol.startsWith("socks")) await socksTunnel(socket, u, o, timeout, signal);
      else {
        const target = `${o.host.includes(":") ? `[${o.host}]` : o.host}:${o.port}`;
        const auth = u.username || u.password ? `Proxy-Authorization: Basic ${Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64")}\r\n` : "";
        const response = readSocket(socket, untilHeader, timeout, 32768, signal);
        socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}\r\n`);
        const head = (await response).toString("latin1"); const status = Number(head.match(/^HTTP\/1\.[01] (\d{3})\b/)?.[1]);
        if (status !== 200) throw new Error(`proxy CONNECT failed (${status || "invalid-response"})`);
      }
    } else { socket = net.connect({ host: o.host, port: o.port }); await waitReady(socket, "connect", timeout, signal); }
    if (o.secure) {
      const servername = o.servername ?? (net.isIP(o.host) ? undefined : o.host);
      socket = tls.connect({ socket, servername, rejectUnauthorized: o.rejectUnauthorized ?? false, ALPNProtocols: ["http/1.1"], minVersion: o.minVersion, maxVersion: o.maxVersion });
      await waitReady(socket, "secureConnect", timeout, signal);
    }
    if (proxy) pool?.reportSuccess(proxy);
    return socket;
  } catch (e) { if (proxy) pool?.reportFailure(proxy); socket?.destroy(); throw e; }
};

export interface RawHttpResult {
  status: number; headers: Record<string, string>; body: string; rawBuffer: Buffer;
  complete: boolean; truncated: boolean; receivedBytes: number; storedBytes: number;
  requestHash: string; responseHash: string; elapsedMs: number; error?: string; receiptId?: string;
}
export const rawHttpExchange = async (url: string, request: Buffer, options: Omit<Partial<TunnelOptions>, "host" | "port" | "secure"> & { maxBytes?: number } = {}): Promise<RawHttpResult> => {
  const u = new URL(url); const started = Date.now(); const cap = options.maxBytes ?? 262144; const signal = options.signal ?? executionSignal();
  let socket: Socket | undefined; let sent = false; let wire = Buffer.alloc(0); let body = Buffer.alloc(0); let status = 0; let headers: Record<string, string> = {}; let complete = false; let truncated = false; let error: string | undefined;
  let receivedBytes = 0;
  try {
    socket = await openTunnel({ host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port) || (u.protocol === "https:" ? 443 : 80), ...options, secure: u.protocol === "https:", signal });
    await new Promise<void>((resolve, reject) => {
      const s = socket!; let settled = false;
      const finish = (e?: Error): void => { if (settled) return; settled = true; clearTimeout(timer); s.removeListener("data", data); s.removeListener("end", ended); s.removeListener("close", ended); s.removeListener("error", fail); signal?.removeEventListener("abort", abort); e ? reject(e) : resolve(); };
      const parse = (ended = false): void => {
        const i = wire.indexOf("\r\n\r\n"); if (i < 0) { if (wire.length > 32768) finish(new Error("response header limit")); else if (ended) finish(new Error("incomplete response header")); return; }
        const head = wire.subarray(0, i).toString("latin1").split("\r\n"); status = Number(head.shift()?.match(/^HTTP\/1\.[01] (\d{3})\b/)?.[1] ?? 0);
        headers = {}; for (const row of head) { const colon = row.indexOf(":"); if (colon > 0) { const k = row.slice(0, colon).toLowerCase(); headers[k] = headers[k] ? `${headers[k]}, ${row.slice(colon + 1).trim()}` : row.slice(colon + 1).trim(); } }
        const raw = wire.subarray(i + 4); receivedBytes = raw.length;
        if (!status) return finish(new Error("invalid HTTP response"));
        const method = request.toString("latin1", 0, request.indexOf(" "));
        if (status >= 100 && status < 200) {
          // Informational (1xx) interim responses carry no final status or
          // body — skip the interim response entirely and keep parsing the
          // stream for the real response that follows.
          const rest = wire.subarray(i + 4);
          wire = rest;
          parse(ended);
          return;
        }
        if (method === "HEAD" || [204, 304].includes(status)) { body = Buffer.alloc(0); complete = true; finish(); return; }
        if (headers["transfer-encoding"]?.toLowerCase().split(/\s*,\s*/).includes("chunked")) {
          const parts: Buffer[] = []; let cursor = 0; let total = 0;
          while (true) {
            const eol = raw.indexOf("\r\n", cursor); if (eol < 0) break;
            const sizeLine = raw.toString("latin1", cursor, eol).split(";")[0]!; if (!/^[\da-f]+$/i.test(sizeLine)) return finish(new Error("invalid chunk size"));
            const size = parseInt(sizeLine, 16); cursor = eol + 2;
            if (size === 0) { const trailer = raw.subarray(cursor); if (trailer.length >= 2 && (trailer.subarray(0, 2).equals(Buffer.from("\r\n")) || trailer.indexOf("\r\n\r\n") >= 0)) complete = true; break; }
            if (raw.length < cursor + size + 2) break;
            if (!raw.subarray(cursor + size, cursor + size + 2).equals(Buffer.from("\r\n"))) return finish(new Error("invalid chunk delimiter"));
            parts.push(raw.subarray(cursor, cursor + size)); total += size; cursor += size + 2;
          }
          body = Buffer.concat(parts, total).subarray(0, cap); truncated = total > cap;
        } else if (headers["content-length"] !== undefined) {
          if (!/^\d+$/.test(headers["content-length"]!)) return finish(new Error("invalid content length"));
          const len = Number(headers["content-length"]); body = raw.subarray(0, Math.min(cap, len)); complete = raw.length >= len; truncated = len > cap && raw.length > cap;
        } else { body = raw.subarray(0, cap); complete = ended; truncated = raw.length > cap; }
        if (truncated) { complete = false; finish(); } else if (complete) finish(); else if (ended) finish(new Error("incomplete response body"));
      };
      const data = (b: Buffer): void => { wire = Buffer.concat([wire, b]); parse(); if (!settled && wire.length > cap + 65536) { truncated = true; complete = false; finish(); } };
      const ended = (): void => parse(true); const fail = (e: Error): void => finish(e); const abort = (): void => finish(aborted());
      const timer = setTimeout(() => finish(new Error("response timeout")), options.timeoutMs ?? 8000);
      s.on("data", data); s.once("end", ended); s.once("close", ended); s.once("error", fail); signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort(); else { sent = true; s.write(request); s.resume(); }
    });
  } catch (e) { error = e instanceof Error ? e.message : String(e); complete = false; }
  finally { socket?.destroy(); }
  const hash = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
  const result: RawHttpResult = { status, headers, body: body.toString("utf8"), rawBuffer: body, complete, truncated, receivedBytes, storedBytes: body.length, requestHash: hash(request), responseHash: hash(body), elapsedMs: Date.now() - started, ...(error ? { error } : {}) };
  if (sent && executionRunId() !== "unbound") {
    const reqText = request.toString("latin1"); const requestHeaders: Record<string, string> = {};
    for (const line of reqText.split("\r\n").slice(1)) { if (!line) break; const i = line.indexOf(":"); if (i > 0) requestHeaders[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim(); }
    result.receiptId = (await recordReceipt({ url, method: reqText.split(" ")[0] ?? "GET", status, requestHash: result.requestHash, responseHash: result.responseHash, complete, principal: principalHash(requestHeaders) })).id;
  }
  return result;
};
