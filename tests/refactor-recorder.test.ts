import { afterEach, describe, expect, it } from "vitest";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createHttpServer, type Server } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ProxyAgent, request } from "undici";
import { TrafficRecorder, getTraffic, searchTraffic } from "../src/domain/trafficRecorder.js";
import { createOrLoadCA } from "../src/domain/mitm.js";

const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => { for (const fn of cleanup.splice(0).reverse()) await fn(); });
const root = async () => {
  const dir = await mkdtemp(join(tmpdir(), "recorder-regression-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
};
const listen = async (server: Server) => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanup.push(async () => { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); });
  return (server.address() as { port: number }).port;
};
const recorder = async (dir: string, mitm = true, options: Record<string, unknown> = {}) => {
  const rec = new TrafficRecorder({ outputRoot: dir, mitm, ...options });
  const port = await rec.start();
  cleanup.push(() => rec.stop());
  const agent = new ProxyAgent({ uri: `http://127.0.0.1:${port}`, requestTls: { rejectUnauthorized: false } });
  cleanup.push(() => agent.destroy());
  return { rec, port, agent };
};
const hash = (body: Buffer) => createHash("sha256").update(body).digest("hex");

 describe("native exchange capture", () => {
  it("MITM GET reaches the origin once and records exactly the client response", async () => {
    const dir = await root();
    const ca = await createOrLoadCA(dir);
    const leaf = ca.sign("127.0.0.1");
    let calls = 0;
    const origin = createHttpsServer({ key: leaf.keyPem, cert: leaf.certPem }, (_req, res) => {
      calls++;
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(Buffer.from(`actual-${calls}`));
    });
    const originPort = await listen(origin);
    const { rec, agent } = await recorder(dir);
    const response = await request(`https://127.0.0.1:${originPort}/once`, { dispatcher: agent });
    const body = Buffer.from(await response.body.arrayBuffer());
    await agent.destroy();
    await rec.stop();
    const records = await searchTraffic({ outputRoot: dir, text: "/once" });
    expect(calls, "capture must never issue a second evidence request").toBe(1);
    expect(records.total).toBe(1);
    const saved = await getTraffic({ outputRoot: dir, id: records.exchanges[0]!.id });
    expect(saved.bodies!.response).toEqual(body);
    expect(saved.exchange!.respBodyHash).toBe(hash(body));
    expect(saved.exchange!.status).toBe(response.statusCode);
  }, 30000);
});
