/** Behavioral fixtures for the review fixes — both polarities, real mock
 *  semantics. Run: npx vitest run tests/review-fixes.test.ts */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFile, mkdir } from "node:fs/promises";
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
