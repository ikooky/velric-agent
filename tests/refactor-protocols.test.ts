import { afterEach, describe, expect, it } from "vitest";
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHmac, generateKeyPairSync } from "node:crypto";
import { probeJwtAttack } from "../src/domain/jwtAttack.js";
import { probeGraphqlAuthz } from "../src/domain/graphqlAuthz.js";
import { buildSchema, parse, validate } from "graphql";

const scratch = "/root/.hermes/cache/scratch";
const root = () => mkdtemp(join(scratch, "protocol-regression-"));
const originalDispatcher = getGlobalDispatcher();
let agent: MockAgent;
afterEach(async () => { setGlobalDispatcher(originalDispatcher); if (agent) await agent.close(); });
const wire = (handler: (opts: any) => { statusCode: number; data: string; responseOptions?: any }) => {
  agent = new MockAgent(); agent.disableNetConnect(); setGlobalDispatcher(agent);
  agent.get("https://protocol.invalid").intercept({ path: /.*/, method: /.*/ }).reply(handler).persist();
};
const token = (alg = "HS256") => {
  const h = Buffer.from(JSON.stringify({ alg, typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ sub: "owner-A", role: "member" })).toString("base64url");
  return `${h}.${p}.${createHmac("sha256", "strong-test-key").update(`${h}.${p}`).digest("base64url")}`;
};
const auth = (o: any) => {
  const h = o.headers;
  if (Array.isArray(h)) { const i = h.findIndex((x: string) => x.toLowerCase() === "authorization"); return i < 0 ? "" : h[i + 1]; }
  return h?.authorization ?? "";
};

describe("I01 JWT authentication oracle", () => {
  it("P01 rejects a public uniform-200 endpoint as an authentication oracle", async () => {
    wire(() => ({ statusCode: 200, data: '{"public":true}' }));
    const r = await probeJwtAttack({ token: token(), endpoint: "https://protocol.invalid/me", outputRoot: await root(), secretCandidates: [] });
    expect(r.attacks.filter(a => a.name !== "weak_secret").every(a => a.verdict === "inconclusive")).toBe(true);
    expect(r.oracle.valid).toBe(false);
  });
  it("P02 preserves stable identity across nonces and actually sends explicit public-key HMAC", async () => {
    const signed = token("RS256"), key = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }).toString();
    const seen: string[] = []; let n = 0;
    wire(o => {
      const t = auth(o).replace(/^Bearer /, ""); seen.push(t);
      const parts = t.split(".");
      const confusion = parts.length === 3 && createHmac("sha256", key).update(`${parts[0]}.${parts[1]}`).digest("base64url") === parts[2];
      return t === signed || confusion ? { statusCode: 200, data: JSON.stringify({ sub: "owner-A", nonce: ++n }) } : { statusCode: 401, data: '{"error":"unauthorized"}' };
    });
    const r = await probeJwtAttack({ token: signed, endpoint: "https://protocol.invalid/me", outputRoot: await root(), publicKeyPem: key });
    expect(r.oracle.valid).toBe(true);
    expect(r.attacks.find(a => a.name === "rs_hs_confusion")?.verdict).toBe("vulnerable");
    expect(seen.filter(t => t === signed)).toHaveLength(2);
    expect(seen.filter(t => !t)).toHaveLength(2);
  });
});

describe("I02 GraphQL valid operations", () => {
  it("P03 builds root AST operations, strips credentials, preserves partial data and skips mutations by default", async () => {
    const out = await root(), schemaFile = join(out, "schema.graphql");
    const sdl = "type Query { profile(id: ID!): User, empty: User } type User { id: ID! name: String } type Mutation { resetAll: Boolean }";
    await writeFile(schemaFile, sdl);
    const sent: any[] = [];
    wire(o => { sent.push(o); const q = JSON.parse(o.body).query; return { statusCode: 200, data: q.includes("profile") ? '{"data":{"profile":{"id":"A","name":null}},"errors":[{"message":"forbidden","path":["profile","name"]}]}' : '{"data":null}' }; });
    const r = await probeGraphqlAuthz({ endpoint: "https://protocol.invalid/graphql", schemaFile, outputRoot: out, headers: { Cookie: "sid=high", Authorization: "Bearer high", "X-Api-Key": "high" }, arguments: { "query:profile": { id: "A" } } } as any);
    expect(sent.length).toBeGreaterThan(0);
    for (const o of sent) {
      const q = JSON.parse(o.body).query;
      expect(validate(buildSchema(sdl), parse(q))).toEqual([]);
      expect(q).not.toContain("mutation");
      expect(JSON.stringify(o.headers).toLowerCase()).not.toMatch(/sid=high|bearer high|x-api-key/);
      expect(JSON.stringify(o.headers)).toContain("application/json");
    }
    expect(r.anonymous.find(a => a.field === "profile")?.dataLeak).toBe(true);
    expect(r.anonymous.find(a => a.field === "empty")?.dataLeak).toBe(false);
    expect((r as any).skipped.some((s: any) => s.field === "resetAll")).toBe(true);
  });
});
