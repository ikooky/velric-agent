import { writeArtifact } from "../adapters/artifacts.js";
import { connect as rawConnect } from "node:net";
import { createHash } from "node:crypto";

/** WebSocket authentication/authorization gap: raw RFC6455 handshake over
 *  TCP (no ws lib) — anonymous connect, Origin cross check, subprotocol
 *  confusion, and post-connect first-frame server push (data leak without
 *  any client auth). */

export interface WsAuthInput {
  readonly url: string;
  readonly outputRoot: string;
  readonly origins?: readonly string[];
  readonly headers?: Record<string, string>;
  readonly timeoutMs?: number;
  /** read window ms after handshake */
  readonly readMs?: number;
}
export interface WsCase {
  readonly label: string;
  readonly handshakeStatus: number | null;
  readonly accepted: boolean;
  readonly secWebSocketAccept: string | null;
  readonly serverPush: string | null;
  readonly note: string;
}
export interface WsAuthResult {
  readonly probed: number;
  readonly anonymousAccepted: boolean;
  readonly crossOriginAccepted: boolean;
  readonly pushWithoutAuth: boolean;
  readonly cases: WsCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const handshake = (host: string, port: number, path: string, origin: string | null, extraHeaders: Record<string, string>): Promise<{ status: number | null; headers: Record<string, string>; body: string; raw: string }> => new Promise((resolve) => {
  const key = createHash("sha1").update(String(Date.now()) + Math.random()).digest("base64").slice(0, 16);
  const sock = rawConnect({ host, port }, () => {
    const lines = [`GET ${path} HTTP/1.1`, `Host: ${host}:${port}`, "Upgrade: websocket", "Connection: Upgrade", `Sec-WebSocket-Key: ${key}`, "Sec-WebSocket-Version: 13"];
    if (origin) lines.push(`Origin: ${origin}`);
    for (const [k, v] of Object.entries(extraHeaders)) lines.push(`${k}: ${v}`);
    sock.write(lines.join("\r\n") + "\r\n\r\n");
  });
  let buf = "";
  const done = () => {
    const head = buf.split("\r\n\r\n")[0] ?? "";
    const status = head.startsWith("HTTP/") ? Number(head.split(" ")[1]) : null;
    const headers: Record<string, string> = {};
    for (const line of head.split("\r\n").slice(1)) { const i = line.indexOf(":"); if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim(); }
    resolve({ status, headers, body: buf.split("\r\n\r\n").slice(1).join("\r\n\r\n"), raw: buf });
    sock.destroy();
  };
  const timer = setTimeout(done, 4000);
  sock.on("data", (d) => { buf += d.toString("latin1"); if (buf.includes("\r\n\r\n")) { clearTimeout(timer); setTimeout(done, 600); } });
  sock.on("error", () => { clearTimeout(timer); sock.destroy(); resolve({ status: null, headers: {}, body: "", raw: "" }); });
});

export const probeWsAuth = async (input: WsAuthInput): Promise<WsAuthResult> => {
  const u = new URL(input.url.replace(/^ws/, "http"));
  const host = u.hostname;
  const port = Number(u.port || (u.protocol === "https:" ? 443 : 80));
  const path = u.pathname + u.search;
  const cases: WsCase[] = [];
  const probe = async (label: string, origin: string | null, extra: Record<string, string>) => {
    const r = await handshake(host, port, path, origin, { ...input.headers, ...extra });
    const accepted = r.status === 101;
    const c: WsCase = { label, handshakeStatus: r.status, accepted, secWebSocketAccept: r.headers["sec-websocket-accept"] ?? null, serverPush: r.body ? r.body.slice(0, 80) : null, note: accepted ? "upgraded" : `status ${r.status}` };
    cases.push(c);
    return c;
  };
  const anon = await probe("anonymous", null, {});
  const noOrigin = await probe("anonymous+no-origin", null, {});
  const cross: WsCase[] = [];
  for (const o of input.origins ?? ["https://evil-velric.example"]) {
    cross.push(await probe(`cross-origin:${o}`, o, {}));
  }
  const subproto = await probe("subprotocol-confusion", null, { "sec-websocket-protocol": "admin" });
  const anonymousAccepted = anon.accepted || noOrigin.accepted;
  const crossOriginAccepted = cross.some(c => c.accepted);
  const pushWithoutAuth = cases.some(c => c.accepted && c.serverPush && c.serverPush.length > 4);
  const artifacts = [
    await writeArtifact(input.outputRoot, "ws_auth.json", JSON.stringify({ cases, anonymousAccepted, crossOriginAccepted, pushWithoutAuth }, null, 2)),
    await writeArtifact(input.outputRoot, "ws_auth.md", ["# WebSocket auth gaps", "", `- anonymous upgrade: **${anonymousAccepted}**`, `- cross-origin upgrade: **${crossOriginAccepted}**`, `- server push w/o auth: **${pushWithoutAuth}**`, "", ...cases.map(c => `- ${c.label}: ${c.note}${c.serverPush ? ` push=${JSON.stringify(c.serverPush.slice(0, 40))}` : ""}`)].join("\n")),
  ];
  return { probed: cases.length, anonymousAccepted, crossOriginAccepted, pushWithoutAuth, cases, artifacts };
};
