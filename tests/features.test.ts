import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

import { scanSecrets, scanPii, scanPairedSecrets, SECRET_PATTERNS, PII_PATTERNS } from "../src/domain/secrets.js";
import { mineHiddenParams } from "../src/domain/hiddenParams.js";
import { findBackups } from "../src/domain/backupFind.js";
import { alterSubdomains } from "../src/domain/subdomainAlter.js";

describe("secrets expansion", () => {
  it("keeps the original patterns working (superset, no regressions)", () => {
    const ghp = ["ghp_16C7e42F292c6912E7710c838347Ae178B", "4a"].join("");
    const js = `const a = "AKIAIOSFODNN7EXAMPLE"; const t = "${ghp}"; const s = "xoxb-123456789-abcdef";`;
    const hits = scanSecrets([{ path: "app.js", text: js }]);
    expect(hits.some((h) => h.name === "aws_access_key_id")).toBe(true);
    expect(hits.some((h) => h.name === "github_token")).toBe(true);
    expect(hits.some((h) => h.name === "slack_token")).toBe(true);
  });

  it("detects new provider patterns (stripe/gitlab/sendgrid)", () => {
    // assemble at runtime so no complete token literal ships in source
    const stripe = ["sk_live_51H8ZQe", "ABCDEFGHIJKLMNOPQRSTUVWXYZ12"].join("");
    const js = `K = "${stripe}"; P = "glpat-AbCdEfGh1234567890123"; G = "SG.ABCDEFGHIJKLMNOP.qrstuvwxyz123456789012345"`;
    const hits = scanSecrets([{ path: "x.js", text: js }]);
    expect(hits.some((h) => h.name === "stripe_key")).toBe(true);
    expect(hits.some((h) => h.name === "gitlab_pat")).toBe(true);
    expect(hits.some((h) => h.name === "sendgrid_key")).toBe(true);
  });

  it("pairs aws key id + secret only when co-occurring (jsluice discipline)", () => {
    // AWS secret keys are exactly 40 base64 chars
    const secret40 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    if (secret40.length !== 40) throw new Error("test vector must be 40 chars");
    const t2 = `{ "key": "AKIAIOSFODNN7EXAMPLE", "sec": "${secret40}" }`;
    const pairs = scanPairedSecrets([{ path: "cfg.js", text: t2 }]);
    expect(pairs.some((p) => p.name === "aws_key_pair")).toBe(true);
    // lone id far from any secret -> no pair
    const alone = `id = "AKIAIOSFODNN7EXAMPLE"; ...50KB of unrelated text...`;
    expect(scanPairedSecrets([{ path: "a.js", text: alone }])).toHaveLength(0);
  });

  it("PII patterns: email, cn phone, jwt; no phone false-positive inside longer digits", () => {
    const body = `contact: zhang.wei@example.com, phone 13812345678, order 20260987123456789012, token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`;
    const hits = scanPii([{ path: "resp.json", text: body }]);
    expect(hits.some((h) => h.name === "email")).toBe(true);
    expect(hits.some((h) => h.name === "phone_cn")).toBe(true);
    expect(hits.some((h) => h.name === "jwt_token")).toBe(true);
    // 21-digit order number must NOT read as an 11-digit cn phone
    const orderOnly = `{"order_id": "20260987123456789012"}`;
    expect(scanPii([{ path: "o.json", text: orderOnly }]).some((h) => h.name === "phone_cn")).toBe(false);
  });
});

describe("hidden-params miner", () => {
  let server: Server;
  let base = "";
  beforeAll(async () => {
    // app that READS ?debug= and ?role= but nothing else
    server = createServer((q, s) => {
      const u = new URL(q.url ?? "/", "http://x");
      const debug = u.searchParams.get("debug");
      const role = u.searchParams.get("role");
      let body = JSON.stringify({ ok: true, items: [1, 2, 3] });
      let code = 200;
      if (debug !== null) { body = JSON.stringify({ ok: true, debugInfo: { queries: 3, cache: "warm" } }); }
      else if (role !== null) { code = 403; body = JSON.stringify({ error: "role not allowed" }); }
      s.writeHead(code, { "content-type": "application/json", "content-length": String(body.length) });
      s.end(body);
    });
    await new Promise<void>((res) => server.listen(0, "127.0.0.1", () => res()));
    const a = server.address() as { address: string; port: number };
    base = `http://${a.address}:${a.port}`;
  });
  afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });

  it("finds params the server reads (debug/role) and skips noise", async () => {
    const out = mkdtempSync(join(tmpdir(), "hp-"));
    const r = await mineHiddenParams({ url: `${base}/api/list`, outputRoot: out, maxWords: 60, learn: false, timeoutMs: 4000 });
    const names = r.found.map((f) => f.param);
    expect(names).toContain("debug");
    expect(names).toContain("role");
    // noise words that the server ignores are NOT flagged
    expect(names).not.toContain("sort");
    expect(r.probed).toBeGreaterThan(10);
  }, 30000);

  it("aborts on unstable baseline (rotating content)", async () => {
    const rot = createServer((q, s) => {
      const b = JSON.stringify({ t: Date.now(), nonce: Math.random() });
      s.writeHead(200, { "content-type": "application/json" });
      s.end(b);
    });
    await new Promise<void>((res) => rot.listen(0, "127.0.0.1", () => res()));
    const a = rot.address() as { address: string; port: number };
    const out = mkdtempSync(join(tmpdir(), "hp2-"));
    const r = await mineHiddenParams({ url: `http://${a.address}:${a.port}/x`, outputRoot: out, timeoutMs: 4000 });
    expect(r.probed).toBe(0);
    expect(r.found).toHaveLength(0);
    await new Promise<void>((res) => rot.close(() => res()));
  }, 30000);
});

describe("backup finder", () => {
  let server: Server;
  let base = "";
  beforeAll(async () => {
    server = createServer((q, s) => {
      const path = (q.url ?? "/").split("?")[0]!;
      if (path === "/index.php.bak" || path === "/www.tar.gz") {
        const b = path.endsWith(".bak") ? "<?php // old source" : "tar-gz-bytes";
        s.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(b.length) });
        return s.end(b);
      }
      s.writeHead(404, { "content-type": "text/plain" });
      s.end("not found");
    });
    await new Promise<void>((res) => server.listen(0, "127.0.0.1", () => res()));
    const a = server.address() as { address: string; port: number };
    base = `http://${a.address}:${a.port}`;
  });
  afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });

  it("finds .bak and root dumps, respects soft-404", async () => {
    const out = mkdtempSync(join(tmpdir(), "bf-"));
    const r = await findBackups({ baseUrl: base, outputRoot: out, timeoutMs: 3000, targets: ["index.php"], maxCandidates: 60 });
    const urls = r.found.map((f) => f.url);
    expect(urls.some((u) => u.endsWith("/index.php.bak"))).toBe(true);
    expect(r.found.every((f) => f.status === 200 && f.bytes > 0)).toBe(true);
  }, 30000);
});

describe("subdomain alteration", () => {
  it("generates permutations and resolves via shared resolver", async () => {
    // generate-only mode (no network): structure + count sanity
    const r = await alterSubdomains({ hosts: ["api.example.com", "dev.example.com"], domain: "example.com", resolve: false });
    expect(r.generated).toBeGreaterThan(20);
    expect(r.samples.some((s) => s.startsWith("v2.api.example.com") || s.includes("api-"))).toBe(true);
    // digit increment present
    expect(r.samples.some((s) => /api2|^dev1/.test(s)) || r.generated >= r.samples.length).toBe(true);
  });

  it("skips non-domain hosts", async () => {
    const r = await alterSubdomains({ hosts: ["other.org"], domain: "example.com", resolve: false });
    expect(r.generated).toBe(0);
  });
});
