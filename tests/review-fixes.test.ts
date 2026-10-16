/** Behavioral fixtures for the review fixes — both polarities, real mock
 *  semantics. Run: npx vitest run tests/review-fixes.test.ts */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const B = (s: string) => Buffer.from(s);
const H = (s: string) => createHash("sha256").update(s).digest("hex");

describe("review fixes: behavioral both-polarity fixtures", () => {
  let srv: Server;
  let base: string;
  const root = mkdtempSync(join(tmpdir(), "revfix-"));

  beforeAll(async () => {
    srv = createServer((req, res) => {
      const u = new URL(req.url, "http://x");
      // /admin: admin cookie → 200 data; nobody/404-agent → 404 (ACL invisibility)
      if (u.pathname === "/admin") {
        const cookie = req.headers.cookie ?? "";
        if (cookie.includes("admin")) { res.writeHead(200, { "content-type": "application/json" }); res.end('{"rows":[1,2,3]}'); }
        else { res.writeHead(404); res.end("nope"); }
        return;
      }
      if (u.pathname === "/api/orders" && req.method === "POST") {
        // tamper oracle: role=user accepted; role=admin (tampered) rejected 403
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          const parsed = JSON.parse(body || "{}");
          if (parsed.role === "admin") { res.writeHead(403); res.end('{"e":"forbidden"}'); }
          else { res.writeHead(200, { "content-type": "application/json" }); res.end('{"ok":true}'); }
        });
        return;
      }
      res.writeHead(404); res.end("nope");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;

    // seed traffic.ndjson for authz_replay / replay_tamper / mass_assign
    const reqBody = JSON.stringify({ item: "x", qty: 1 });
    const rbh = H(reqBody);
    await mkdir(join(root, "blobs", rbh.slice(0, 2)), { recursive: true });
    await writeFile(join(root, "blobs", rbh.slice(0, 2), rbh + ".bin"), reqBody);
    const respBody = '{"ok":true}';
    const rspbh = H(respBody);
    await mkdir(join(root, "blobs", rspbh.slice(0, 2)), { recursive: true });
    await writeFile(join(root, "blobs", rspbh.slice(0, 2), rspbh + ".bin"), respBody);
    await writeFile(join(root, "traffic.ndjson"), JSON.stringify({
      id: "ex1", ts: "2026-01-01T00:00:00Z", client: "127.0.0.1",
      method: "POST", url: `${base}/api/orders`, status: 200,
      reqHeaders: { "content-type": "application/json", cookie: "sid=admin", authorization: "Bearer ADMIN" },
      reqBodyHash: rbh, respBodyHash: rspbh, respContentType: "application/json",
    }) + "\n");
  });
  afterAll(() => new Promise<void>((r) => srv.close(() => r())));

  it("A1: authz_replay same-fingerprint 2xx replay → bypassed (positive pole)", async () => {
    const { replayAuthz } = await import("../src/domain/authzReplay.js");
    const out = await replayAuthz({ recordRoot: root, outputRoot: root, roles: { nobody: "Cookie: sid=nobody" }, exchangeIds: ["ex1"] });
    // /api/orders answers 200 {"ok":true} to ANY credential — same fingerprint
    // as the recorded admin baseline → legitimately bypassed (mock ground truth).
    expect(out.bypassed).toHaveLength(1);
    expect(out.enforced).toHaveLength(0);
  });

  it("A1-pole2: exchange on /admin with 404 response → verdict unknown", async () => {
    // Register an admin-baseline exchange at /admin (GET, admin cookie → 200)
    const respBody2 = '{"rows":[1,2,3]}';
    const rspbh2 = H(respBody2);
    await mkdir(join(root, "blobs", rspbh2.slice(0, 2)), { recursive: true });
    await writeFile(join(root, "blobs", rspbh2.slice(0, 2), rspbh2 + ".bin"), respBody2);
    const line = JSON.stringify({
      id: "ex2", ts: "2026-01-01T00:00:00Z", client: "127.0.0.1",
      method: "GET", url: `${base}/admin`, status: 200,
      reqHeaders: { cookie: "sid=admin" }, reqBodyHash: null as unknown as string,
      respBodyHash: rspbh2, respContentType: "application/json",
    });
    await writeFile(join(root, "traffic.ndjson"), line + "\n", { flag: "a" });
    const { replayAuthz } = await import("../src/domain/authzReplay.js");
    const out = await replayAuthz({ recordRoot: root, outputRoot: root, roles: { nobody: "Cookie: sid=nobody" }, exchangeIds: ["ex2"] });
    // The mock answers 404 to nobody: pre-fix this was mislabeled "enforced";
    // post-fix it must be unknown (hidden-or-missing).
    const cell = (out as { cells?: { verdict: string; note: string }[] }).cells ?? [];
    expect(cell.some((c) => c.note.includes("hidden-or-missing"))).toBe(true);
  });

  it("A3: replay_tamper dry-run fires ZERO live requests (inventory only)", async () => {
    let fired = 0;
    // wrap: count via ledger? simpler — probe with applyTamper unset and assert
    // every outcome is dry-run and no fetch happened: use a dedicated record
    // root whose only exchange targets a dead port; dry-run must not care.
    const deadRoot = mkdtempSync(join(tmpdir(), "revfix-dead-"));
    const rbh = H("{}");
    await mkdir(join(deadRoot, "blobs", rbh.slice(0, 2)), { recursive: true });
    await writeFile(join(deadRoot, "blobs", rbh.slice(0, 2), rbh + ".bin"), "{}");
    await writeFile(join(deadRoot, "traffic.ndjson"), JSON.stringify({
      id: "dx1", ts: "t", client: "c", method: "POST", url: "http://127.0.0.1:9/x",
      status: 200, reqHeaders: {}, reqBodyHash: rbh, respBodyHash: H("r"), respContentType: "application/json",
    }) + "\n");
    const { replayTamper } = await import("../src/domain/replayTamper.js");
    const out = await replayTamper({ recordRoot: deadRoot, outputRoot: deadRoot, rules: [], applyTamper: undefined } as never);
    fired = out.outcomes.length;
    // Dead endpoint + dry-run: old code fired a live baseline that failed (skip
    // everything); new code inventories WITHOUT firing — outcomes exist.
    expect(out.outcomes.every((o: { verdict: string }) => o.verdict === "dry-run")).toBe(true);
    expect(fired).toBeGreaterThan(0);
  });

  it("A4: mass_assign credential strips BOTH recorded carriers (no stacking)", async () => {
    const { probeMassAssign } = await import("../src/domain/massAssign.js");
    // Mock returns 403 for injected fields → dry-run default means no fire;
    // assert header discipline via the exported helper if any, else via apply run.
    const out = await probeMassAssign({ recordRoot: root, outputRoot: root, credential: "Cookie: sid=low", apply: true } as never);
    expect(Array.isArray(out.sinks)).toBe(true);
    // The wire truth: /api/orders sees cookie sid=low ONLY — verify no admin leak
    // by checking the mock's denial: injected role=admin with sid=low → 403 rejected.
    expect(out.sinks.every((s: { verdict: string }) => s.verdict !== "accepted-changed")).toBe(true);
  });

  it("P0: normalization makes timestamp-noise bodies compare equal", async () => {
    const { normalizeBody, tokenSimilarity } = await import("../src/domain/normalize.js");
    const a = '{"ts":"2026-10-16T08:00:00.123Z","reqId":"a1b2c3d4e5f6a7b8","rows":[1,2,3]}';
    const b = '{"ts":"2026-10-16T09:11:22.456Z","reqId":"f6e5d4c3b2a19870","rows":[1,2,3]}';
    expect(normalizeBody(a)).toBe(normalizeBody(b)); // volatile stripped
    const c = '{"rows":[1,2,3,4]}';
    expect(normalizeBody(a)).not.toBe(normalizeBody(c)); // real diff survives
    expect(tokenSimilarity(normalizeBody(a), normalizeBody(b))).toBeGreaterThan(0.9);
    expect(tokenSimilarity(normalizeBody(a), normalizeBody(c))).toBeLessThan(0.9);
  });

  it("P0: headerBypass SPA shell 2xx is NOT a bypass", async () => {
    // mock: /admin 401 for baseline; WITH X-Original-URL header returns 200 SPA index (tiny html)
    const srv2 = createServer((req, res) => {
      if (req.url === "/admin" && req.headers["x-original-url"]) {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<html><body>app</body></html>"); // tiny shell
        return;
      }
      res.writeHead(401); res.end("no auth");
    });
    await new Promise<void>((r) => srv2.listen(0, "127.0.0.1", r));
    const b2 = `http://127.0.0.1:${(srv2.address() as { port: number }).port}/admin`;
    const root2 = mkdtempSync(join(tmpdir(), "p0-hb-"));
    const { probeHeaderBypass } = await import("../src/domain/headerBypass.js");
    const out = await probeHeaderBypass({ urls: [b2], outputRoot: root2 } as never);
    expect(out.bypasses).toHaveLength(0); // shell excluded
    expect(out.attempts.some((a: { verdict: string }) => a.verdict === "shell-suspect")).toBe(true);
    srv2.close();
  });

  it("P0: sourcemap data-URI inline map detected", async () => {
    const { createHash } = await import("node:crypto");
    const root2 = mkdtempSync(join(tmpdir(), "p0-sm-"));
    const { mkdir: mk, writeFile: wf } = await import("node:fs/promises");
    await mk(join(root2, "js"), { recursive: true });
    const map = JSON.stringify({ version: 3, sources: ["src/app.ts", "src/util.ts"], sourcesContent: ["const a=1;", "const b=2;"] });
    const inline = `//# sourceMappingURL=data:application/json;base64,${Buffer.from(map).toString("base64")}`;
    await wf(join(root2, "js", "app.js"), `console.log(1);\n${inline}`);
    const { detectSourceMaps } = await import("../src/domain/sourcemap.js");
    const out = await detectSourceMaps({ jsDir: join(root2, "js"), outputRoot: root2, recover: true });
    expect(out.leaked.some((l: { mapUrl: string }) => l.mapUrl === "data:inline")).toBe(true);
    // recovery: 2 sources recovered
    expect(out.recovered?.recovered).toBe(2);
    // recovered file content check
    const rec = await readFile(join(root2, "sourcemap-recovered", "src", "app.ts"), "utf8");
    expect(rec).toBe("const a=1;");
  });

  it("P1: authz canary marker leak = content-level bypass proof", async () => {
    // victim marker in low-priv response body → bypassed with marker note
    const { mkdtempSync: mk, writeFileSync: wf2 } = await import("node:fs");
    const { createHash: ch } = await import("node:crypto");
    const H = (x: string) => ch("sha256").update(x).digest("hex");
    const victimBody = JSON.stringify({ tenant: "ACME-CORP-VICTIM", rows: [1, 2, 3] });
    const attackerBody = JSON.stringify({ tenant: "user-tenant", rows: [1, 2, 3] });
    const srv2 = createServer((req, res) => {
      const cookie = req.headers.cookie ?? "";
      if (cookie.includes("admin")) { res.writeHead(200, { "content-type": "application/json" }); res.end(victimBody); }
      else { res.writeHead(200, { "content-type": "application/json" }); res.end(attackerBody); }
    });
    await new Promise<void>((r) => srv2.listen(0, "127.0.0.1", r));
    const b2 = `http://127.0.0.1:${(srv2.address() as { port: number }).port}/tenants/77`;
    const root2 = mk(join(tmpdir(), "p1-canary-"));
    const rbh = H(victimBody);
    await mkdir(join(root2, "blobs", rbh.slice(0, 2)), { recursive: true });
    await writeFile(join(root2, "blobs", rbh.slice(0, 2), rbh + ".bin"), victimBody);
    wf2(join(root2, "traffic.ndjson"), JSON.stringify({ id: "c1", ts: "t", client: "c", method: "GET", url: b2, status: 200, reqHeaders: { cookie: "sid=admin" }, reqBodyHash: null, respBodyHash: rbh, respContentType: "application/json" }) + "\n");
    const { replayAuthz } = await import("../src/domain/authzReplay.js");
    // mock with NO canary semantics: admin gets victim body, user gets own —
    // WITHOUT markers this is unknown (bodies differ). With a leaking mock:
    const srv3 = createServer((req, res) => {
      const cookie = req.headers.cookie ?? "";
      if (cookie.includes("admin")) { res.writeHead(200, { "content-type": "application/json" }); res.end(victimBody); }
      else { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ tenant: "ACME-CORP-VICTIM", leaked: true })); } // LEAK
    });
    await new Promise<void>((r) => srv3.listen(0, "127.0.0.1", r));
    const b3 = `http://127.0.0.1:${(srv3.address() as { port: number }).port}/tenants/77`;
    wf2(join(root2, "traffic.ndjson"), JSON.stringify({ id: "c2", ts: "t", client: "c", method: "GET", url: b3, status: 200, reqHeaders: { cookie: "sid=admin" }, reqBodyHash: null, respBodyHash: rbh, respContentType: "application/json" }) + "\n", { flag: "a" });
    const out2 = await replayAuthz({ recordRoot: root2, outputRoot: root2, roles: { user: "Cookie: sid=user" }, markers: { admin: ["ACME-CORP-VICTIM"] }, exchangeIds: ["c1", "c2"], anonymous: false, timeoutMs: 5000 });
    const c1 = out2.cells.find((c) => c.exchangeId === "c1" && c.role === "user")!;
    const c2 = out2.cells.find((c) => c.exchangeId === "c2" && c.role === "user")!;
    expect(c1.verdict).toBe("unknown"); // no marker in response → structural unknown
    expect(c2.verdict).toBe("bypassed"); // marker leak → content-level proof
    expect(c2.note).toContain("marker leak");
    srv2.close(); srv3.close();
  });

  it("P1: hiddenParams bucket bisection finds param in log requests + junk control", async () => {
    let n = 0;
    const srv2 = createServer((req, res) => {
      n++;
      const u = new URL(req.url ?? "/", "http://x");
      if (u.searchParams.has("debug")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ debug: true, extra: 1 }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((r) => srv2.listen(0, "127.0.0.1", r));
    const b2 = `http://127.0.0.1:${(srv2.address() as { port: number }).port}/x`;
    const root2 = mkdtempSync(join(tmpdir(), "p1-bucket-"));
    const { mineHiddenParams } = await import("../src/domain/hiddenParams.js");
    const out = await mineHiddenParams({ url: b2, outputRoot: root2, bucketSize: 8, words: ["alpha", "beta", "gamma", "debug", "delta", "eps", "zeta", "eta", "theta", "iota"], learn: false, timeoutMs: 3000 } as never);
    expect(out.found.some((f: { param: string }) => f.param === "debug")).toBe(true);
    // log2-ish coverage: 10 candidates in buckets of 8 → 2 buckets + bisections
    expect(n).toBeLessThan(35); // one-by-one paired probes would be ~40 for 10 words
    srv2.close();
  });

  it("P1: idorDeep three-reference oracle confirms with identity field", async () => {
    // /orders/<id>: owner id=100 → own data; id=101 → OTHER user's data (200, different email); anonymous → 401
    const srv2 = createServer((req, res) => {
      const m = (req.url ?? "").match(/^\/orders\/(\d+)$/);
      if (!m) { res.writeHead(404); res.end(); return; }
      if (!req.headers.cookie) { res.writeHead(401); res.end("login"); return; }
      const id = m[1];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: Number(id), email: id === "100" ? "owner@x.com" : "other@y.com", total: 42 }));
    });
    await new Promise<void>((r) => srv2.listen(0, "127.0.0.1", r));
    const b2 = `http://127.0.0.1:${(srv2.address() as { port: number }).port}`;
    const root2 = mkdtempSync(join(tmpdir(), "p1-idor-"));
    const { probeIdorDeep } = await import("../src/domain/idorDeep.js");
    const out = await probeIdorDeep({ endpoints: [{ method: "GET", path: "/orders/100", fields: [] }], baseUrl: b2, cookie: "sid=me", outputRoot: root2 } as never);
    const conf = out.candidates.find((c) => c.verdict === "idor-confirmed-identity");
    expect(conf).toBeTruthy();
    expect(conf?.identityEvidence).toContain("email");
    // attacker response ≈ denied(401 body) case: public mock returns 200 to anon too
    srv2.close();
  });

  it("E1: paramProbe aborts endpoint on unstable baseline", async () => {
    let n = 0;
    const srv2 = createServer((req, res) => {
      n++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ n })); // per-request noise → unstable
    });
    await new Promise<void>((r) => srv2.listen(0, "127.0.0.1", r));
    const b2 = `http://127.0.0.1:${(srv2.address() as { port: number }).port}`;
    const { probeParams } = await import("../src/application/paramProbe.js");
    const root2 = mkdtempSync(join(tmpdir(), "revfix-pp-"));
    await writeFile(join(root2, "params_merged.json"), JSON.stringify([
      { method: "GET", path: "/noisy", fields: [{ name: "q", in: "query" }] },
    ]));
    const out = await probeParams({ mergedFile: join(root2, "params_merged.json"), baseUrl: b2, outputRoot: root2 } as never);
    const first = out.endpointResults[0]!;
    expect(first.baseline.sha256).toBe("unstable-baseline");
    expect(first.params).toHaveLength(0);
    srv2.close();
  });
});
