import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { WebSocket } from "undici";

/** WebSocket origin-check probe (CSWSH prescreen): attempt the upgrade with
 *  a hostile Origin and with no Origin. An upgrade that succeeds under a
 *  cross-origin Origin = missing origin validation. Also notes where auth
 *  material is carried (query param / subprotocol header) from the URL. */

export interface WsOriginInput {
  /** ws(s):// endpoint URL. */
  readonly url: string;
  readonly outputRoot: string;
  readonly headers?: Record<string, string>;
  readonly timeoutMs?: number;
}

export interface WsOriginResult {
  readonly url: string;
  readonly authCarried: "query-param" | "subprotocol" | "none-visible";
  readonly variants: { origin: string; upgraded: boolean; closeCode: number | null; note: string }[];
  readonly vulnerable: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const tryUpgrade = (url: string, origin: string | null, timeoutMs: number): Promise<{ upgraded: boolean; closeCode: number | null; err: string | null }> =>
  new Promise((resolve) => {
    let settled = false;
    const done = (upgraded: boolean, closeCode: number | null, err: string | null): void => {
      if (settled) return;
      settled = true;
      try { ws.close(); } catch { /* already gone */ }
      resolve({ upgraded, closeCode, err });
    };
    const headers: Record<string, string> = {};
    if (origin !== null) headers.origin = origin;
    let ws: WebSocket;
    try {
      ws = new WebSocket(url, { headers, protocols: [] } as never);
    } catch (e) {
      resolve({ upgraded: false, closeCode: null, err: String(e) });
      return;
    }
    const timer = setTimeout(() => done(false, null, "timeout"), timeoutMs);
    ws.addEventListener("open", () => { clearTimeout(timer); done(true, null, null); });
    ws.addEventListener("error", () => { clearTimeout(timer); done(false, null, "handshake-rejected"); });
    ws.addEventListener("close", (ev) => { clearTimeout(timer); const code = Number((ev as { code?: number }).code ?? 0); done(false, code > 0 ? code : null, null); });
  });

export const probeWsOrigin = async (input: WsOriginInput): Promise<WsOriginResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const timeout = input.timeoutMs ?? 8000;
  const u = new URL(input.url);
  const hasTokenQuery = [...u.searchParams.keys()].some((k) => /token|auth|key|sig|ticket/i.test(k));
  const authCarried: WsOriginResult["authCarried"] = hasTokenQuery ? "query-param" : "none-visible";

  const evilOrigin = `https://evil-velric.example.com`;
  const variants: WsOriginResult["variants"] = [];

  const evil = await tryUpgrade(input.url, evilOrigin, timeout);
  variants.push({ origin: evilOrigin, upgraded: evil.upgraded, closeCode: evil.closeCode, note: evil.upgraded ? "cross-origin upgrade ACCEPTED" : (evil.err ?? "rejected") });
  const noOrigin = await tryUpgrade(input.url, null, timeout);
  variants.push({ origin: "(none)", upgraded: noOrigin.upgraded, closeCode: noOrigin.closeCode, note: noOrigin.upgraded ? "upgrade accepted without Origin header" : (noOrigin.err ?? "rejected") });

  const vulnerable = evil.upgraded;
  const result: WsOriginResult = { url: input.url, authCarried, variants, vulnerable: evil.upgraded, artifacts: [] };
  const path = join(input.outputRoot, "ws_origin.json");
  const body = JSON.stringify(result, null, 2);
  await writeFile(path, body);
  result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
  return result;
};
