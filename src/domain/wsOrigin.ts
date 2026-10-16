import { createHash, randomBytes } from "node:crypto";
import { openTunnel, readSocket } from "../adapters/rawTunnel.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { executionRunId, executionSignal, recordReceipt } from "../core/execution.js";
import { principalHash } from "../core/credentials.js";

export interface WsOriginInput {
  readonly url: string; readonly outputRoot: string; readonly headers?: Record<string, string>;
  readonly timeoutMs?: number; readonly proxy?: string; readonly rejectUnauthorized?: boolean; readonly signal?: AbortSignal;
}
interface UpgradeResult { upgraded: boolean; status: number; err: string | null; complete: boolean; requestHash?: string; responseHash?: string; receiptId?: string }
export interface WsOriginResult {
  readonly url: string; readonly vulnerable: boolean;
  readonly crossOriginAccepted: boolean; readonly outcome: "candidate" | "not-accepted" | "inconclusive";
  readonly authCarried: "query-param" | "header" | "none-visible";
  readonly variants: ({ origin: string | null } & UpgradeResult)[];
  readonly artifacts: { path: string; bytes: number }[];
}
const hash = (b: string | Buffer): string => createHash("sha256").update(b).digest("hex");
const tryUpgrade = async (input: WsOriginInput, origin: string | null): Promise<UpgradeResult> => {
  const u = new URL(input.url); const secure = ["wss:", "https:"].includes(u.protocol); const key = randomBytes(16).toString("base64");
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.headers ?? {})) {
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n]/.test(value)) throw new Error("invalid WebSocket header");
    if (!/^(host|connection|upgrade|origin|sec-websocket-.*|proxy-authorization)$/i.test(name)) headers[name.toLowerCase()] = value;
  }
  const request = [`GET ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`, "Upgrade: websocket", "Connection: Upgrade", `Sec-WebSocket-Key: ${key}`, "Sec-WebSocket-Version: 13", ...(origin === null ? [] : [`Origin: ${origin}`]), ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), "", ""].join("\r\n");
  let socket: import("node:net").Socket | undefined; let sent = false; let response: Buffer = Buffer.alloc(0); let result: UpgradeResult;
  try {
    socket = await openTunnel({ host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port) || (secure ? 443 : 80), secure, proxy: input.proxy, rejectUnauthorized: input.rejectUnauthorized, timeoutMs: input.timeoutMs, signal: input.signal });
    const receive = readSocket(socket, b => { const i = b.indexOf("\r\n\r\n"); return i < 0 ? -1 : i + 4; }, input.timeoutMs ?? 8000, 32768, input.signal ?? executionSignal());
    socket.write(request); sent = true; response = await receive;
    const lines = response.toString("latin1").split("\r\n"); const status = Number(lines.shift()?.match(/^HTTP\/1\.[01] (\d{3})\b/)?.[1] ?? 0);
    const responseHeaders = new Map<string, string[]>();
    for (const line of lines) { const i = line.indexOf(":"); if (i > 0) { const k = line.slice(0, i).toLowerCase(); responseHeaders.set(k, [...responseHeaders.get(k) ?? [], line.slice(i + 1).trim()]); } }
    const one = (name: string): string => (responseHeaders.get(name) ?? []).join(",");
    const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    const valid = status === 101 && one("upgrade").toLowerCase() === "websocket" && one("connection").toLowerCase().split(/\s*,\s*/).includes("upgrade") && responseHeaders.get("sec-websocket-accept")?.length === 1 && one("sec-websocket-accept") === accept;
    result = { status, upgraded: valid, complete: status > 0, err: status === 101 && !valid ? "invalid-websocket-handshake" : status === 0 ? "invalid-http-response" : null };
  } catch (e) { result = { status: 0, upgraded: false, complete: false, err: e instanceof Error ? e.message : String(e) }; }
  finally { socket?.destroy(); }
  result.requestHash = hash(request); result.responseHash = hash(response);
  if (sent && executionRunId() !== "unbound") result.receiptId = (await recordReceipt({ url: input.url, method: "GET", status: result.status, requestHash: result.requestHash, responseHash: result.responseHash, complete: result.complete, principal: principalHash(headers) })).id;
  return result;
};
export const probeWsOrigin = async (input: WsOriginInput): Promise<WsOriginResult> => {
  const u = new URL(input.url); if (!["ws:", "wss:", "http:", "https:"].includes(u.protocol)) throw new Error("unsupported WebSocket URL");
  const queryAuth = [...u.searchParams.keys()].some(k => /token|auth|key|sig|ticket/i.test(k));
  const headerAuth = Object.keys(input.headers ?? {}).some(k => /cookie|authorization|api-key/i.test(k));
  const hostile = "https://cross-origin.invalid";
  const variants = [{ origin: hostile, ...await tryUpgrade(input, hostile) }, { origin: null, ...await tryUpgrade(input, null) }];
  const crossOriginAccepted = variants[0]!.upgraded;
  const result: WsOriginResult = { url: input.url, vulnerable: false, crossOriginAccepted, outcome: crossOriginAccepted ? "candidate" : variants.some(v => v.err) ? "inconclusive" : "not-accepted", authCarried: queryAuth ? "query-param" : headerAuth ? "header" : "none-visible", variants, artifacts: [] };
  return { ...result, artifacts: [await writeArtifact(input.outputRoot, "ws_origin.json", JSON.stringify(result, null, 2))] };
};
