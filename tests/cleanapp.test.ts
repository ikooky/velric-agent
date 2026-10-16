/** Clean-app false-positive gate (pentest-ai tests/cleanapp discipline): a
 *  deliberately VULNERABLE-FREE application must yield ZERO findings across
 *  every verdict path. Golden samples lock schema drift; this locks the
 *  FALSE-POSITIVE rate. A finding here means a detector overclaims.
 *
 *  The fixture app is a correctly-implemented one:
 *  - every route requires a valid session cookie; low-priv sessions get 403 on
 *    admin routes; object reads are scoped to the owning session (IDOR-safe)
 *  - no leaks, no debug pages, no reflection, stable bodies (no volatile ids
 *    EXCEPT a rotation-safe one path that must land in unknown, not findings)
 *  Run: npx vitest run tests/cleanapp.test.ts */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const H = (s: string) => createHash("sha256").update(s).digest("hex");

// Two principals with disjoint object ownership — CORRECT authz everywhere.
const USERS: Record<string, { role: string; orders: Record<string, { id: number; email: string; total: number }> }> = {
  "sid=admin1": { role: "admin", orders: { "100": { id: 100, email: "admin@corp.example", total: 42 } } },
  "sid=user1": { role: "user", orders: { "200": { id: 200, email: "user@corp.example", total: 7 } } },
};

describe("clean-app false-positive gate (zero findings on a correct app)", () => {
  let srv: Server;
  let base: string;
  const root = mkdtempSync(join(tmpdir(), "cleanapp-"));

  beforeAll(async () => {
    srv = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      const cookie = (req.headers.cookie ?? "").match(/sid=[\w]+/)?.[0] ?? "";
      const me = USERS[cookie];
      const json = (code: number, body: unknown): void => {
        res.writeHead(code, { "content-type": "application/json" });
        res.end(typeof body === "string" ? body : JSON.stringify(body));
      };
      // login endpoint is the only public route
      if (u.pathname === "/login") { json(200, { ok: true }); return; }
      if (!me) { json(401, { error: "login required" }); return; }
      if (u.pathname.startsWith("/admin") && me.role !== "admin") { json(403, { error: "forbidden" }); return; }
      const m = u.pathname.match(/^\/orders\/(\d+)$/);
      if (m) {
        const own = me.orders[m[1]!];
        if (!own) { json(404, { error: "not found" }); return; } // correct: invisible objects 404
        json(200, own);
        return;
      }
      if (u.pathname === "/whoami") { json(200, { role: me.role, email: `${me.role}@corp.example` }); return; }
      // query params never change output (no hidden params)
      json(200, { ok: true, fixed: true });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(srv.address() as { port: number }).port}`;

    // record admin traffic for authz replay
    const resp = JSON.stringify(USERS["sid=admin1"]!.orders["100"]!);
    const rbh = H(resp);
    await mkdir(join(root, "blobs", rbh.slice(0, 2)), { recursive: true });
    await writeFile(join(root, "blobs", rbh.slice(0, 2), rbh + ".bin"), resp);
    writeFileSync(join(root, "traffic.ndjson"), [
      JSON.stringify({ id: "a1", ts: "t", client: "c", method: "GET", url: `${base}/orders/100`, status: 200, reqHeaders: { cookie: "sid=admin1" }, reqBodyHash: null, respBodyHash: rbh, respContentType: "application/json" }),
      JSON.stringify({ id: "a2", ts: "t", client: "c", method: "GET", url: `${base}/admin/stats`, status: 200, reqHeaders: { cookie: "sid=admin1" }, reqBodyHash: null, respBodyHash: H('{"stats":1}'), respContentType: "application/json" }),
      JSON.stringify({ id: "a3", ts: "t", client: "c", method: "GET", url: `${base}/whoami`, status: 200, reqHeaders: { cookie: "sid=admin1" }, reqBodyHash: null, respBodyHash: H(JSON.stringify({ role: "admin", email: "admin@corp.example" })), respContentType: "application/json" }),
    ].join("\n") + "\n");
    // blobs for the other two exchanges
    for (const b of ['{"stats":1}', JSON.stringify({ role: "admin", email: "admin@corp.example" })]) {
      const h = H(b);
      await mkdir(join(root, "blobs", h.slice(0, 2)), { recursive: true });
      await writeFile(join(root, "blobs", h.slice(0, 2), h + ".bin"), b);
    }
  });
  afterAll(() => new Promise<void>((r) => srv.close(() => r())));

  it("authz_replay: user role gets ZERO bypassed on a correctly enforced app", async () => {
    const { replayAuthz } = await import("../src/domain/authzReplay.js");
    const out = await replayAuthz({ recordRoot: root, outputRoot: root, roles: { user: "Cookie: sid=user1" }, timeoutMs: 5000 });
    expect(out.bypassed.filter((c) => c.role === "user")).toHaveLength(0);
    // /admin/stats correctly denied; /orders/100 correctly 404 (invisible)
    expect(out.cells.find((c) => c.url.endsWith("/admin/stats") && c.role === "user")?.verdict).toBe("enforced");
  });

  it("idorDeep: cross-tenant order id yields ZERO idor-confirmed verdicts", async () => {
    const { probeIdorDeep } = await import("../src/domain/idorDeep.js");
    const out = await probeIdorDeep({
      endpoints: [{ method: "GET", path: "/orders/200", fields: [] }],
      baseUrl: base, cookie: "sid=user1", outputRoot: root, objectIds: ["100"],
    } as never);
    const confirmed = out.candidates.filter((c) => c.verdict.startsWith("idor-confirmed"));
    expect(confirmed).toHaveLength(0); // variant 100 → correct 404
    expect(out.candidates.every((c) => ["not-found", "denied", "skip", "same-response"].includes(c.verdict))).toBe(true);
  });

  it("headerBypass: no spoofable header opens anything on a correct app", async () => {
    const { probeHeaderBypass } = await import("../src/domain/headerBypass.js");
    const out = await probeHeaderBypass({ urls: [`${base}/admin/stats`], outputRoot: root, cookie: "sid=user1" } as never);
    expect(out.bypasses).toHaveLength(0);
  });

  it("hiddenParams: stable no-op endpoint yields ZERO found params", async () => {
    const { mineHiddenParams } = await import("../src/domain/hiddenParams.js");
    const out = await mineHiddenParams({ url: `${base}/dashboard`, outputRoot: root, cookie: "sid=user1", words: ["debug", "admin", "internal", "test", "trace"], learn: false, timeoutMs: 3000 } as never);
    expect(out.found).toHaveLength(0);
  });
});
