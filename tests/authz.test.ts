import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

import { replayAuthz } from "../src/domain/authzReplay.js";
import { probeMassAssign } from "../src/domain/massAssign.js";

// Minimal app simulating the three enforcement shapes Autorize distinguishes:
//   /admin/data   — enforced: 403 for non-admin cookie, 200 for admin
//   /shared/data  — bypass:   200 same body for everyone
//   /sneaky/data  — 200 denial-shaped body for low-priv (content, not status)
//   /profile      — mass-assignment sink: binds injected isAdmin field
//   /profile-safe — rejects injected fields (unknown field -> 400)
let server: Server;
let base = "";
const ADMIN_COOKIE = "session=admin42";
const USER_COOKIE = "session=user7";

const req: { method: string; url: string; headers: Record<string, string>; body: string } = { method: "", url: "", headers: {}, body: "" };

beforeAll(async () => {
  server = createServer((q, s) => {
    let body = "";
    q.on("data", (c) => { body += c; });
    q.on("end", () => {
      req.method = q.method ?? "GET";
      req.url = q.url ?? "/";
      req.headers = q.headers as Record<string, string>;
      req.body = body;
      const cookie = q.headers.cookie ?? "";
      const isAdmin = cookie.includes("admin42");
      const json = (code: number, obj: unknown) => { s.writeHead(code, { "content-type": "application/json" }); s.end(JSON.stringify(obj)); };

      if (req.url === "/admin/data") {
        if (isAdmin) return json(200, { secret: "admin-only", rows: 42 });
        return json(403, { error: "forbidden" });
      }
      if (req.url === "/shared/data") {
        return json(200, { shared: "ok" });
      }
      if (req.url === "/sneaky/data") {
        if (isAdmin) return json(200, { data: "real", rows: 10 });
        return json(200, { message: "Access denied: insufficient permissions" });
      }
      if (req.url === "/redirect/data") {
        if (isAdmin) return json(200, { data: "x" });
        s.writeHead(302, { location: "/login" });
        return s.end();
      }
      if (req.url === "/profile" && (req.method === "POST" || req.method === "PATCH" || req.method === "PUT")) {
        // sink: binds everything, echoes the stored record
        let parsed: Record<string, unknown> = {};
        try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { /* */ }
        return json(200, { id: 7, name: parsed.name ?? "n", isAdmin: parsed.isAdmin ?? false, role: parsed.role ?? "user", saved: true });
      }
      if (req.url === "/profile-safe" && req.method === "POST") {
        let parsed: Record<string, unknown> = {};
        try { parsed = JSON.parse(body) as Record<string, unknown>; } catch { /* */ }
        const allowed = new Set(["name", "email"]);
        const extra = Object.keys(parsed).filter((k) => !allowed.has(k));
        if (extra.length > 0) return json(400, { error: `unknown field ${extra[0]}` });
        return json(200, { id: 8, name: parsed.name ?? "n" });
      }
      s.writeHead(404); s.end("nf");
    });
  });
  await new Promise<void>((res) => server.listen(0, "127.0.0.1", () => res()));
  const addr = server.address() as { address: string; port: number };
  base = `http://${addr.address}:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((res) => server.close(() => res()));
});

const blobWrite = (root: string, content: string): { hash: string; bytes: number } => {
  const hash = createHash("sha256").update(content).digest("hex");
  const dir = join(root, "blobs", hash.slice(0, 2));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${hash}.bin`), content);
  return { hash, bytes: Buffer.byteLength(content) };
};

/** Record admin-session traffic in the trafficRecorder ndjson+blobs format. */
const mkRecord = (dir: string): void => {
  const body1 = JSON.stringify({ name: "Updated Name" });
  const respAdminData = JSON.stringify({ secret: "admin-only", rows: 42 });
  const respShared = JSON.stringify({ shared: "ok" });
  const respSneaky = JSON.stringify({ data: "real", rows: 10 });
  const lines: string[] = [];
  const add = (id: string, method: string, url: string, reqBody: string | null, status: number, respBody: string) => {
    const rb = reqBody ? blobWrite(dir, reqBody) : null;
    const pb = blobWrite(dir, respBody);
    lines.push(JSON.stringify({
      ts: new Date().toISOString(), id, method, url,
      reqHeaders: { cookie: ADMIN_COOKIE, "content-type": "application/json" },
      reqBodyHash: rb?.hash ?? null, reqBodyBytes: rb?.bytes ?? 0,
      status, respHeaders: { "content-type": "application/json" },
      respBodyHash: pb.hash, respBodyBytes: pb.bytes, via: "http-capture",
    }));
  };
  add("e1", "GET", `${base}/admin/data`, null, 200, respAdminData);
  add("e2", "GET", `${base}/shared/data`, null, 200, respShared);
  add("e3", "GET", `${base}/sneaky/data`, null, 200, respSneaky);
  add("e4", "POST", `${base}/profile`, body1, 200, JSON.stringify({ id: 7, name: "Updated Name", isAdmin: false, role: "user", saved: true }));
  add("e5", "POST", `${base}/profile-safe`, body1, 200, JSON.stringify({ id: 8, name: "Updated Name" }));
  writeFileSync(join(dir, "traffic.ndjson"), lines.join("\n") + "\n");
};

describe("authz_replay (Autorize-style)", () => {
  it("classifies enforced / bypassed / denial-shaped per role", async () => {
    const rec = mkdtempSync(join(tmpdir(), "authz-rec-"));
    const out = mkdtempSync(join(tmpdir(), "authz-out-"));
    mkRecord(rec);

    const r = await replayAuthz({
      recordRoot: rec, outputRoot: out,
      roles: { user: `Cookie: ${USER_COOKIE}`, anon: "Cookie: x=y" },
      timeoutMs: 5000,
    });

    const cell = (id: string, role: string) => r.cells.find((c) => c.exchangeId === id && c.role === role)!;
    // /admin/data: user -> 403 enforced
    expect(cell("e1", "user").verdict).toBe("enforced");
    // /shared/data answers 200 to EVERYONE including anonymous (the mock has no
    // auth on it) — the anonymous third state correctly downgrades the user
    // bypass to unknown-public: this is a PUBLIC endpoint, not an authz gap.
    expect(cell("e2", "__anonymous__").verdict).toBe("bypassed");
    expect(cell("e2", "user").verdict).toBe("unknown");
    expect(cell("e2", "user").note).toContain("public");
    // /sneaky/data: 200 denial-shaped body = enforced (content, not status)
    expect(cell("e3", "user").verdict).toBe("enforced");
    // POST /profile is writable by ANY session in the mock — including
    // anonymous (no auth on the route). The anonymous third state correctly
    // downgrades user's bypass to unknown-public: publicly writable endpoint.
    expect(cell("e4", "__anonymous__").verdict).toBe("bypassed");
    expect(cell("e4", "user").verdict).toBe("unknown");
    // credential headers replaced, not stacked: recorded cookie must NOT leak
    expect(cell("e1", "user").replayStatus).toBe(403);
  }, 20000);

  it("redirect-to-login scores enforced, not allowed", async () => {
    const rec = mkdtempSync(join(tmpdir(), "authz-rec2-"));
    const out = mkdtempSync(join(tmpdir(), "authz-out2-"));
    const respRedirect = JSON.stringify({ data: "x" });
    const hash = blobWrite(rec, respRedirect).hash;
    require("node:fs").writeFileSync(join(rec, "traffic.ndjson"), JSON.stringify({
      ts: new Date().toISOString(), id: "e9", method: "GET", url: `${base}/redirect/data`,
      reqHeaders: { cookie: ADMIN_COOKIE }, reqBodyHash: null, reqBodyBytes: 0,
      status: 200, respHeaders: {}, respBodyHash: hash, respBodyBytes: respRedirect.length, via: "http-capture",
    }) + "\n");
    const r = await replayAuthz({ recordRoot: rec, outputRoot: out, roles: { user: `Cookie: ${USER_COOKIE}` }, timeoutMs: 5000 });
    expect(r.cells.find((c) => c.role === "user")!.verdict).toBe("enforced");
    expect(r.cells.find((c) => c.role === "user")!.redirectedAway).toBe(true);
  }, 20000);

  it("readOnly filters mutating methods", async () => {
    const rec = mkdtempSync(join(tmpdir(), "authz-rec3-"));
    const out = mkdtempSync(join(tmpdir(), "authz-out3-"));
    mkRecord(rec);
    const r = await replayAuthz({ recordRoot: rec, outputRoot: out, roles: { user: `Cookie: ${USER_COOKIE}` }, readOnly: true, timeoutMs: 5000 });
    expect(r.replayed).toBe(3); // e1-e3 GET only; e4/e5 POST excluded
  }, 20000);
});

describe("mass_assign radar", () => {
  it("flags reflected fields on the sink endpoint and rejection on the safe one", async () => {
    const rec = mkdtempSync(join(tmpdir(), "ma-rec-"));
    const out = mkdtempSync(join(tmpdir(), "ma-out-"));
    mkRecord(rec);

    const r = await probeMassAssign({
      recordRoot: rec, outputRoot: out,
      credential: `Cookie: ${USER_COOKIE}`,
      fields: ["isAdmin", "role", "user_id"],
      apply: true, timeoutMs: 5000,
    });

    // /profile binds isAdmin=true -> reflected
    const sinkFields = r.outcomes.filter((o) => o.url.endsWith("/profile") && o.verdict === "reflected").map((o) => o.field);
    expect(sinkFields).toContain("isAdmin");
    // /profile-safe rejects unknown fields -> rejected
    const safe = r.outcomes.filter((o) => o.url.endsWith("/profile-safe"));
    expect(safe.length).toBeGreaterThan(0);
    expect(safe.every((o) => o.verdict === "rejected")).toBe(true);
    // sinks aggregate only reflected/accepted-changed
    expect(r.sinks.every((o) => o.verdict === "reflected" || o.verdict === "accepted-changed")).toBe(true);
  }, 20000);

  it("dry-run inventories injectable fields without firing", async () => {
    const rec = mkdtempSync(join(tmpdir(), "ma-rec2-"));
    const out = mkdtempSync(join(tmpdir(), "ma-out2-"));
    mkRecord(rec);
    const r = await probeMassAssign({ recordRoot: rec, outputRoot: out, fields: ["isAdmin"], timeoutMs: 5000 });
    expect(r.outcomes.every((o) => o.verdict === "dry-run")).toBe(true);
    expect(r.outcomes.some((o) => o.field === "isAdmin")).toBe(true);
    expect(r.sinks).toHaveLength(0);
  }, 20000);
});
