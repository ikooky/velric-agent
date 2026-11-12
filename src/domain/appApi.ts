import { createHmac } from "node:crypto";
import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Mobile-app signed-request protocol: replay the exact header scheme a Flutter
 *  / native app uses once the scheme + key are known (from flutter-analyze or a
 *  packet capture). Signs every request (path-only or full canonical form),
 *  carries the session token, and decrypts the app's response envelope when the
 *  body-cipher key is supplied. This is the bridge from "reverse engineered the
 *  protocol" to "every app API callable from the CLI". */

export interface AppApiInput {
  /** Request list, one per call. */
  readonly calls: readonly AppApiCall[];
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface AppApiCall {
  readonly name: string;
  readonly url: string;
  readonly method?: string;
  readonly body?: string;
  /** HMAC scheme parameters. */
  readonly scheme: {
    readonly header: string;
    readonly algo: "sha1" | "sha256";
    readonly key: string;
    /** Message layout; placeholders {nonce} {path} {ts} {token} {ua}. */
    readonly message: string;
    /** Header value layout; same placeholders. */
    readonly headerValue: string;
  };
  readonly token?: string;
  readonly userAgent?: string;
  readonly extraHeaders?: Record<string, string>;
  /** AES-256-CBC response envelope key (bridge-cipher). When set, `data`
   *  fields are decrypted with the derived key/iv (dual-SHA256 split scheme). */
  readonly bodyCipherKey?: string;
}

export interface AppApiCallResult {
  readonly name: string;
  readonly url: string;
  readonly status: number;
  readonly ms: number;
  readonly bodyPrefix: string;
  readonly decrypted?: unknown;
}

export interface AppApiResult {
  readonly results: AppApiCallResult[];
  readonly artifacts: { path: string; bytes: number }[];
}

import { createHash, createDecipheriv, randomUUID } from "node:crypto";

/** Bridge cipher: k || nonce12 → halves → SHA256 mix → AES-256-CBC key/iv.
 *  Layout follows the common "interface key + 12-byte salt prefix" envelope. */
const bridgeDecrypt = (key: string, b64: string): unknown => {
  const k = Buffer.from(key, "utf8");
  const n = Buffer.from(b64.trim(), "base64");
  if (n.length < 16) throw new Error("ciphertext too short");
  const sha = (b: Buffer): Buffer => createHash("sha256").update(b).digest();
  const i = Buffer.concat([k, n.subarray(0, 12)]);
  const half = i.length >> 1;
  const l = sha(i).subarray(8, 24);
  const m = Buffer.concat([l, i.subarray(0, half)]);
  const g = Buffer.concat([i.subarray(half), l]);
  const keyOut = Buffer.concat([sha(m).subarray(0, 8), sha(g).subarray(8, 24), sha(m).subarray(24)]);
  const iv = Buffer.concat([sha(g).subarray(0, 4), sha(m).subarray(12, 20), sha(g).subarray(28)]);
  const d = createDecipheriv("aes-256-cbc", keyOut, iv);
  const out = Buffer.concat([d.update(n.subarray(12)), d.final()]);
  const text = out.toString("utf8");
  return text === "nil" ? null : JSON.parse(text);
};

export const callAppApi = async (input: AppApiInput): Promise<AppApiResult> => {
  const results: AppApiCallResult[] = [];
  for (const call of input.calls) {
    const u = new URL(call.url);
    const ts = Math.floor(Date.now() / 1000);
    const nonce = randomUUID().replaceAll("-", "");
    const ua = call.userAgent ?? "okhttp/4.12.0";
    const fill = (tpl: string): string => tpl
      .replaceAll("{nonce}", nonce)
      .replaceAll("{path}", u.pathname)
      .replaceAll("{ts}", String(ts))
      .replaceAll("{token}", call.token ?? "")
      .replaceAll("{ua}", ua);
    const msg = fill(call.scheme.message).replace(/^JSON:/, (m) => m); // JSON: prefix = stringify {..} form
    const message = call.scheme.message.startsWith("JSON:")
      ? JSON.stringify({ nonce, path: u.pathname, timestamp: ts, token: call.token ?? "", userAgent: ua })
      : msg;
    const signature = createHmac(call.scheme.algo, call.scheme.key).update(message).digest("hex");
    const headers: Record<string, string> = {
      ...(call.extraHeaders ?? {}),
      "user-agent": ua,
      [call.scheme.header]: fill(call.scheme.headerValue).replace("{sign}", signature),
    };
    if (call.token) headers.authorization = call.token;
    if (call.body) headers["content-type"] = "application/json";
    const t0 = Date.now();
    const r = await fetchUrl(call.url, {
      method: call.method ?? (call.body ? "POST" : "GET"),
      body: call.body,
      headers,
      maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12_000, maxBytes: 2 * 1024 * 1024,
    });
    const ms = Date.now() - t0;
    let decrypted: unknown;
    if (call.bodyCipherKey && r.status === 200) {
      try {
        const doc = JSON.parse(r.body) as { code?: number; data?: string };
        if (typeof doc.data === "string" && doc.data.length > 24) decrypted = bridgeDecrypt(call.bodyCipherKey, doc.data);
      } catch { /* not an envelope */ }
    }
    results.push({ name: call.name, url: call.url, status: r.status, ms, bodyPrefix: r.body.slice(0, 200), decrypted });
  }
  const body = JSON.stringify({ results }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "app_api.json", body);
  return { results, artifacts: [artifact] };
};
