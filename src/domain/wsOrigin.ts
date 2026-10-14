import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { connect as tlsConnect } from "node:tls";
import { connect as netConnect } from "node:net";

/** WebSocket cross-origin upgrade probe (CSWSH prescreen). The undici
 *  browser-style WebSocket ignores a headers option and undici's Client
 *  rejects upgrade handshakes, so the hostile Origin is delivered via a
 *  RAW socket handshake — the only transport that actually puts the
 *  header on the wire. */

export interface WsOriginInput {
  readonly url: string;
  readonly outputRoot: string;
  readonly headers?: Record<string, string>;
  readonly timeoutMs?: number;
}

export interface WsOriginResult {
  readonly url: string;
  readonly vulnerable: boolean;
  readonly authCarried: "query-param" | "none-visible";
  readonly variants: { origin: string | null; upgraded: boolean; status: number; err: string | null }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const tryUpgrade = (
  url: string,
  origin: string | null,
  timeoutMs: number,
  extraHeaders: Record<string, string>,
): Promise<{ upgraded: boolean; status: number; err: string | null }> =>
  new Promise((resolve) => {
    let u: URL;
    try { u = new URL(url); } catch { resolve({ upgraded: false, status: 0, err: "bad-url" }); return; }
    const secure = u.protocol === "wss:" || u.protocol === "https:";
    const port = Number(u.port) || (secure ? 443 : 80);
    const key = randomBytes(16).toString("base64");
    const reqLines = [
      `GET ${u.pathname}${u.search} HTTP/1.1`,
      `Host: ${u.host}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
      ...(origin !== null ? [`Origin: ${origin}`] : []),
      ...Object.entries(extraHeaders).map(([k, v]) => `${k}: ${v}`),
      "",
      "",
    ];
    const raw = reqLines.join("\r\n");

    let settled = false;
    const done = (r: { upgraded: boolean; status: number; err: string | null }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* gone */ }
      resolve(r);
    };
    const timer = setTimeout(() => done({ upgraded: false, status: 0, err: "timeout" }), timeoutMs);

    const onData = (chunk: Buffer): void => {
      const head = chunk.toString("latin1").split("\r\n")[0] ?? "";
      const status = Number(head.split(" ")[1] ?? 0);
      if (status === 101) done({ upgraded: true, status, err: null });
      else done({ upgraded: false, status, err: null });
    };

    let sock: import("node:net").Socket;
    if (secure) {
      sock = tlsConnect({ host: u.hostname, port, rejectUnauthorized: false, servername: u.hostname }, () => { sock.write(raw); });
    } else {
      sock = netConnect({ host: u.hostname, port }, () => { sock.write(raw); });
    }
    sock.once("data", onData);
    sock.once("error", (e: Error) => done({ upgraded: false, status: 0, err: String(e.message).slice(0, 120) }));
  });

export const probeWsOrigin = async (input: WsOriginInput): Promise<WsOriginResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const timeout = input.timeoutMs ?? 8000;
  const u = new URL(input.url);
  const hasTokenQuery = [...u.searchParams.keys()].some((k) => /token|auth|key|sig|ticket/i.test(k));
  const authCarried: WsOriginResult["authCarried"] = hasTokenQuery ? "query-param" : "none-visible";

  const evilOrigin = "https://evil-velric.example.com";
  const extra = input.headers ?? {};
  const evil = await tryUpgrade(input.url, evilOrigin, timeout, extra);
  const none = await tryUpgrade(input.url, null, timeout, extra);

  // Vulnerable prescreen: hostile-origin upgrade accepted. A query-param
  // token raises impact (cookie-less sites often put auth in the URL).
  const vulnerable = evil.upgraded;
  const variants: WsOriginResult["variants"] = [
    { origin: evilOrigin, ...evil },
    { origin: null, ...none },
  ];

  const result: WsOriginResult = { url: input.url, vulnerable, authCarried, variants, artifacts: [] };
  const body = JSON.stringify(result, null, 2);
  const path = join(input.outputRoot, "ws_origin.json");
  await writeFile(path, body);
  return { ...result, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
