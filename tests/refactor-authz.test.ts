import { afterEach, describe, it, expect } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { normalizeBody, tokenSimilarity, charSimilarity, learnNormalization } from "../src/domain/normalize.js";
import { replayAuthz } from "../src/domain/authzReplay.js";
import { withExecution } from "../src/core/execution.js";

const roots: string[] = [];
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });
const tempRoot = async (): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "refactor-authz-"));
  roots.push(root);
  return root;
};
const H = (s: string): string => createHash("sha256").update(s).digest("hex");
const blob = async (root: string, body: string): Promise<string> => {
  const hash = H(body);
  await mkdir(join(root, "blobs", hash.slice(0, 2)), { recursive: true });
  await writeFile(join(root, "blobs", hash.slice(0, 2), `${hash}.bin`), body);
  return hash;
};
const record = async (url: string, input: { method?: string; body?: string; headers?: Record<string, string>; response?: string } = {}): Promise<string> => {
  const root = await tempRoot();
  const response = input.response ?? '{"owner":"victim","id":100,"rows":[1,2,3]}';
  await writeFile(join(root, "traffic.ndjson"), JSON.stringify({
    id: "e1", method: input.method ?? "GET", url, reqHeaders: input.headers ?? { Cookie: "sid=victim" },
    reqBodyHash: input.body === undefined ? null : await blob(root, input.body),
    reqBodyBytes: input.body === undefined ? 0 : Buffer.byteLength(input.body),
    status: 200, respBodyHash: await blob(root, response), respBodyBytes: Buffer.byteLength(response),
  }) + "\n");
  return root;
};
const json = (res: ServerResponse, status: number, value: unknown): void => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(value));
};
const withServer = async (handler: (req: IncomingMessage, res: ServerResponse) => void, run: (base: string) => Promise<void>): Promise<void> => {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try { await run(base); }
  finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
};

describe("identity-safe normalization", () => {
  it("preserves UUID identity and case", () => {
    expect(normalizeBody('{"owner":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","name":"Alice"}'))
      .not.toBe(normalizeBody('{"owner":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","name":"alice"}'));
  });
  it("does not equate numbers, non-Latin text, or uncomparable tokens", () => {
    expect(tokenSimilarity('[1,2,3]', '[4,5,6]')).toBe(0);
    expect(tokenSimilarity('张三', '李四')).toBe(0);
    expect(tokenSimilarity('', '')).toBe(0);
  });
  it("learns volatility only outside identity subtrees", () => {
    const a = JSON.stringify({ timestamp: 1, tenant: { requestId: "owner-a" }, requestId: "a".repeat(32) });
    const b = JSON.stringify({ timestamp: 2, tenant: { requestId: "owner-b" }, requestId: "b".repeat(32) });
    const profile = learnNormalization([a, b]);
    expect(profile.volatilePaths).toContain("/timestamp");
    expect(profile.volatilePaths).not.toContain("/tenant/requestId");
    expect(profile.volatilePaths).not.toContain("/requestId");
    expect(normalizeBody(a, profile)).not.toBe(normalizeBody(b, profile));
  });
  it("does not give perfect token similarity to capped equal prefixes", () => {
    const prefix = "item ".repeat(8001);
    expect(tokenSimilarity(prefix + "owner-a", prefix + "owner-b")).toBeLessThan(1);
  });
  it("bounds large comparisons without equating truncated prefixes", () => {
    const a = "x".repeat(30000) + "Alice";
    const b = "x".repeat(30000) + "Bob";
    const start = performance.now();
    expect(charSimilarity(a, b)).toBeLessThan(1);
    expect(charSimilarity("a".repeat(20000), "b".repeat(20000))).toBe(0);
    expect(performance.now() - start).toBeLessThan(500);
  });
});

describe("authz replay proof boundaries", () => {
  it("keeps valid own-profile responses suspect despite high structural overlap", async () => {
    const ownerCalls: string[] = [];
    await withServer((req, res) => {
      const cookie = req.headers.cookie ?? "";
      ownerCalls.push(cookie);
      if (!cookie) return json(res, 401, { error: "login required" });
      json(res, 200, { owner: cookie.includes("victim") ? "victim" : "attacker", id: 100, a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8 });
    }, async (base) => {
      const root = await record(`${base}/profile`, { response: JSON.stringify({ owner: "victim", id: 100, a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8 }) });
      const out = await withExecution({ tool: "authz-test" }, () => replayAuthz({ recordRoot: root, outputRoot: root, roles: { user: "sid=attacker" }, anonymous: false, apply: true }));
      expect(out.bypassed).toHaveLength(0);
      expect(out.cells.find((c) => c.role === "user")?.verdict).toBe("suspect");
      expect(ownerCalls.filter((cookie) => cookie === "sid=victim")).toHaveLength(2);
    });
  });
});
