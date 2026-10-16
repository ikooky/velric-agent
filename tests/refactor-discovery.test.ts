import "../src/adapters/http.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { deflateSync, gzipSync } from "node:zlib";
import { zipSync } from "fflate";
import { promises as dns } from "node:dns";

const scratch = "/root/.hermes/cache/scratch";
const roots: string[] = [];
const root = async () => { const p = await mkdtemp(join(scratch, "discovery-")); roots.push(p); return p; };
const oldDispatcher = getGlobalDispatcher();
let agent: MockAgent | undefined;
const http = (origin = "https://fixture.invalid") => {
  agent = new MockAgent(); agent.disableNetConnect(); setGlobalDispatcher(agent);
  return agent.get(origin);
};
const object = (type: string, payload: Buffer | string, size?: number) => {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const plain = Buffer.concat([Buffer.from(`${type} ${size ?? data.length}\0`), data]);
  return { sha: createHash("sha1").update(plain).digest("hex"), raw: deflateSync(plain) };
};
afterEach(async () => { setGlobalDispatcher(oldDispatcher); await agent?.close(); agent = undefined; vi.restoreAllMocks(); await Promise.all(roots.splice(0).map(p => rm(p, { recursive: true, force: true }))); });

describe("discovery recovery native regressions", () => {
  it("F01 backup candidates never change origin and reserve root dumps within budget", async () => {
    const pool = http(); const requested: string[] = [];
    pool.intercept({ path: /.*/ }).reply(options => { requested.push(String(options.path)); return { statusCode: 404, data: "not found" }; }).persist();
    for (const origin of ["https://fixture.invalidadmin", "https://foreign.invalid"]) agent!.get(origin).intercept({ path: /.*/ }).reply(404, "not found").persist();
    const { findBackups } = await import("../src/domain/backupFind.js");
    const out = await findBackups({ baseUrl: "https://fixture.invalid", outputRoot: await root(), targets: ["admin/", "https://foreign.invalid/file"], maxCandidates: 30, timeoutMs: 100 });
    expect(out.probed).toBe(30);
    expect(requested).toContain("/admin.bak");
    expect(requested).toContain("/backup.zip");
    expect(requested.every(p => !p.includes("foreign.invalid"))).toBe(true);
    expect(requested).not.toContain("/admin/admin.bak");
  });

  it("F03 keeps real equal-size/status resources and all cluster members with manual redirects", async () => {
    const pool = http(); const requests: string[] = [];
    pool.intercept({ path: /.*/ }).reply(options => {
      const p = String(options.path); requests.push(p);
      if (p === "/redirect") return { statusCode: 302, data: "", responseOptions: { headers: { location: "/login" } } };
      const data = p === "/forbidden" ? "missing" : /^\/(?:alpha|bravo|delta|real)$/.test(p) ? "present" : "missing";
      return { statusCode: p === "/forbidden" ? 403 : 200, data, responseOptions: { headers: { "content-type": "text/plain" } } };
    }).persist();
    const { probePaths } = await import("../src/domain/pathProbe.js");
    const paths = await probePaths({ baseUrl: "https://fixture.invalid/app/?x=1", paths: ["/alpha", "/bravo", "/delta", "/redirect", "https://foreign.invalid/x"], outputRoot: await root() });
    expect(paths.found.map(f => f.path)).toEqual(expect.arrayContaining(["/alpha", "/bravo", "/delta", "/redirect"]));
    expect(paths.found.find(f => f.path === "/redirect")?.status).toBe(302);
    expect(requests).not.toContain("/login");
    expect(requests.every(p => !p.includes("?x=1"))).toBe(true);
    const { dirFuzz } = await import("../src/domain/dirFuzz.js");
    const fuzz = await dirFuzz({ url: "https://fixture.invalid/FUZZ", words: ["real", "forbidden", "fake"], outputRoot: await root(), maxWords: 3 });
    expect(fuzz.hits.map(f => f.status)).toEqual([200, 403]);
    expect(fuzz.hits.map(f => f.url)).toContain("https://fixture.invalid/real");
  });

  it("F03 requires product evidence rather than a login or same-shape JSON", async () => {
    const pool = http();
    pool.intercept({ path: /.*/ }).reply(options => {
      const p = String(options.path);
      const data = p === "/v3/api-docs" ? '{"openapi":"3.0.0","paths":{}}' : p === "/admin" ? '<title>Login</title><form><input type="password"></form>' : '{"message":"missing"}';
      return { statusCode: 200, data, responseOptions: { headers: { "content-type": p === "/admin" ? "text/html" : "application/json" } } };
    }).persist();
    const { probeAdminSurface } = await import("../src/domain/adminSurface.js");
    const result = await probeAdminSurface({ baseUrl: "https://fixture.invalid/nested/?a=1", outputRoot: await root() });
    expect(result.found.map(f => new URL(f.url).pathname)).toEqual(["/v3/api-docs"]);
    expect(result.found[0]?.evidence).toContain("openapi");
  });

  it("dirty URL members are skipped individually in both refinement stages", async () => {
    const { dedupeUrls, classifyUrls } = await import("../src/domain/urlRefine.js");
    const urls = ["not a URL", "https://fixture.invalid/item?id=2", "file:///etc/passwd", "https://u:p@fixture.invalid/x", "http://[", null, "https://fixture.invalid/x?q=term"] as unknown as string[];
    const out = dedupeUrls({ urls });
    expect(out.urls).toEqual([urls[1], urls[6]]);
    expect(classifyUrls(urls).urls.map(u => u.url)).toEqual([urls[1], urls[6]]);
  });

  it("F04 recovers fetched relative maps using bundle provenance and inline percent maps", async () => {
    const pool = http(); const requested: string[] = [];
    const out = await root(); await mkdir(join(out, "js"));
    const file = join(out, "js", "renamed.js");
    await writeFile(file, "//# sourceMappingURL=app.js.map");
    const map = JSON.stringify({ version: 3, sources: ["src/remote.ts"], sourcesContent: ["remote-source"] });
    pool.intercept({ path: /.*/ }).reply(options => {
      requested.push(String(options.path));
      return { statusCode: String(options.path) === "/assets/app.js.map" ? 200 : 404, data: map };
    }).persist();
    const inline = JSON.stringify({ version: 3, sources: ["src/inline.ts"], sourcesContent: ["inline-source"] });
    await writeFile(join(out, "js", "inline.js"), `//# sourceMappingURL=data:application/json,${encodeURIComponent(inline)}`);
    const { detectSourceMaps } = await import("../src/domain/sourcemap.js");
    const result = await detectSourceMaps({ outputRoot: out, baseUrl: "https://fixture.invalid/", recover: true, bundles: [{ file, url: "https://fixture.invalid/assets/app.js" }] } as Parameters<typeof detectSourceMaps>[0]);
    expect(result.recovered).toEqual({ maps: 2, recovered: 2, missing: 0 });
    expect(await readFile(join(out, "sourcemap-recovered/src/remote.ts"), "utf8")).toBe("remote-source");
    expect(await readFile(join(out, "sourcemap-recovered/src/inline.ts"), "utf8")).toBe("inline-source");
    expect(result.leaked.find(m => m.file === file)).toMatchObject({ bundleUrl: "https://fixture.invalid/assets/app.js", mapUrl: "https://fixture.invalid/assets/app.js.map" });
    expect(requested).toContain("/assets/app.js.map");
  });

  it("F04 isolates non-string sources and preserves sanitization collisions in a manifest", async () => {
    const out = await root(), maps = join(out, "maps"); await mkdir(maps);
    await writeFile(join(maps, "one.map"), JSON.stringify({ sources: [42, null, "src/a?.ts", "src/a*.ts", "../escape.ts", "src/good.ts"], sourcesContent: ["bad", "bad", "one", "two", "escape", "good"] }));
    const { recoverSourceMaps } = await import("../src/domain/sourceRecover.js");
    const result = await recoverSourceMaps({ mapDir: maps, outputRoot: out });
    expect(result.recovered).toBe(3); expect(result.missing).toBe(3);
    expect(new Set(result.files).size).toBe(3);
    const contents = await Promise.all(result.files.map(f => readFile(f, "utf8")));
    expect(contents.sort()).toEqual(["good", "one", "two"]);
    const manifest = JSON.parse(await readFile(join(out, "sourcemap_recovered.json"), "utf8"));
    expect(manifest.manifest.some((m: { collisionWith?: string }) => !!m.collisionWith)).toBe(true);
  });

  it("F02 rejects ZIP metadata lies and bounds actual ZIP/TAR output across archives", async () => {
    const pool = http();
    const ordinary = Buffer.from(zipSync({ "one.txt": Buffer.alloc(64, 65) }));
    const lie = Buffer.from(ordinary);
    const central = lie.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    lie.writeUInt32LE(0, central + 24); lie.writeUInt32LE(0, 22);
    pool.intercept({ path: "/lie.zip" }).reply(200, lie);
    pool.intercept({ path: "/big.zip" }).reply(200, ordinary);
    pool.intercept({ path: "/many.tgz" }).reply(200, gzipSync(Buffer.alloc(4096)));
    const { unpackBackups } = await import("../src/domain/backupUnpack.js");
    const out = await unpackBackups({ urls: ["https://fixture.invalid/lie.zip", "https://fixture.invalid/big.zip", "https://fixture.invalid/many.tgz"], outputRoot: await root(), maxDecompressedBytes: 32, maxEntryBytes: 32 } as Parameters<typeof unpackBackups>[0]);
    expect(out.unpacked).toHaveLength(0);
    expect((out as unknown as { failures: unknown[] }).failures).toHaveLength(3);
  });

  it("F02 validates Git hashes/lengths and restores shared blobs without re-fetching", async () => {
    const blob = object("blob", "same-content");
    const badLength = object("blob", "bad-content", 2);
    const forgedSha = "b".repeat(40);
    const tree = object("tree", Buffer.concat([Buffer.from(`100644 a.txt\0`), Buffer.from(blob.sha, "hex"), Buffer.from(`100644 b.txt\0`), Buffer.from(blob.sha, "hex"), Buffer.from(`100644 invalid.txt\0`), Buffer.from(badLength.sha, "hex"), Buffer.from(`100644 forged.txt\0`), Buffer.from(forgedSha, "hex")]));
    const commit = object("commit", `tree ${tree.sha}\n\nfixture\n`);
    const pool = http(), fetched: string[] = [];
    const objects = new Map([blob, badLength, tree, commit].map(o => [o.sha, o.raw])); objects.set(forgedSha, blob.raw);
    pool.intercept({ path: /.*/ }).reply(options => {
      const p = String(options.path);
      if (p.endsWith("/.git/config")) return { statusCode: 200, data: "[core]\nrepositoryformatversion=0\n" };
      if (p.endsWith("/.git/HEAD")) return { statusCode: 200, data: commit.sha };
      const m = p.match(/\/objects\/([0-9a-f]{2})\/([0-9a-f]{38})$/);
      if (m) { const sha = m[1]! + m[2]!; fetched.push(sha); const raw = objects.get(sha); return { statusCode: raw ? 200 : 404, data: raw ?? "" }; }
      return { statusCode: 404, data: "" };
    }).persist();
    const { restoreGit } = await import("../src/domain/gitRestore.js");
    const out = await restoreGit({ baseUrl: "https://fixture.invalid/app/?q=1", outputRoot: await root(), maxObjects: 5 });
    expect(out.filesRestored).toBe(2); expect(out.objectsRecovered).toBe(3);
    expect(await readFile(join(out.workDir, "a.txt"), "utf8")).toBe("same-content");
    expect(await readFile(join(out.workDir, "b.txt"), "utf8")).toBe("same-content");
    expect(fetched.filter(sha => sha === blob.sha)).toHaveLength(1);
    expect(fetched).toHaveLength(5);
    const limited = await restoreGit({ baseUrl: "https://fixture.invalid/app/", outputRoot: await root(), maxObjects: 2 });
    expect(limited.objectsRecovered).toBe(2); expect(limited.filesRestored).toBe(0);
  });

  it("F04 tries dead URLs but rejects archive challenge pages as recovered content", async () => {
    const pool = http();
    pool.intercept({ path: /.*/ }).reply(410, "gone").persist();
    agent!.get("https://archive.org").intercept({ path: /.*/ }).reply(options => {
      const target = new URL(`https://archive.org${options.path}`).searchParams.get("url")!;
      return { statusCode: 200, data: JSON.stringify({ archived_snapshots: { closest: { available: true, url: `https://web.archive.org/web/20250101000000/${target}` } } }) };
    }).persist();
    agent!.get("https://web.archive.org").intercept({ path: /.*/ }).reply(options => ({ statusCode: 200, data: String(options.path).endsWith("/good") ? "<html><title>Saved page</title>Content</html>" : "<title>Just a moment</title>challenge-platform" })).persist();
    for (const host of ["archive.ph", "archive.md", "archive.li", "archive.is"]) agent!.get(`https://${host}`).intercept({ path: /.*/ }).reply(200, "Just a moment challenge-platform".repeat(50)).persist();
    const { recoverUrl } = await import("../src/domain/archive.js");
    const rejected = await recoverUrl({ url: "https://fixture.invalid/bad", outputRoot: await root() });
    expect(rejected.recoveredFrom).toBeNull();
    const recovered = await recoverUrl({ url: "https://fixture.invalid/good", outputRoot: await root() });
    expect(recovered.recoveredFrom).toBe("wayback");
    expect(await readFile(recovered.artifacts[0]!.path, "utf8")).toContain("Saved page");
  });

  it("F05 uses explicit resolvers for A/AAAA/CNAME and retains non-wildcard hosts", async () => {
    http();
    agent!.get("https://crt.sh").intercept({ path: /.*/ }).reply(200, '[{"common_name":"ct.fixture.invalid"}]').persist();
    const system4 = vi.spyOn(dns, "resolve4"), system6 = vi.spyOn(dns, "resolve6"), systemCname = vi.spyOn(dns, "resolveCname");
    const custom4 = vi.spyOn(dns.Resolver.prototype, "resolve4").mockImplementation(async (host: string) => host.startsWith("api.") ? ["192.0.2.2"] : host.startsWith("alias.") || host.startsWith("v6.") ? [] : ["192.0.2.1"]);
    const custom6 = vi.spyOn(dns.Resolver.prototype, "resolve6").mockImplementation(async (host: string) => host.startsWith("v6.") ? ["2001:db8::2"] : host.startsWith("alias.") || host.startsWith("api.") ? [] : ["2001:db8::1"]);
    const customCname = vi.spyOn(dns.Resolver.prototype, "resolveCname").mockImplementation(async (host: string) => host.startsWith("alias.") ? ["real.external.invalid"] : host.startsWith("api.") || host.startsWith("v6.") ? [] : ["wild.external.invalid"]);
    const { discoverSubdomains } = await import("../src/domain/subdomains.js");
    const result = await discoverSubdomains({ domain: "fixture.invalid", resolvers: ["127.0.0.1"], wordlist: ["api", "alias", "v6", "missing"], outputRoot: await root() });
    expect(result.wildcardDns).toBe(true);
    expect(result.bruteFound.map(h => h.host).sort()).toEqual(["alias.fixture.invalid", "api.fixture.invalid", "v6.fixture.invalid"]);
    expect(result.bruteFound.find(h => h.host.startsWith("v6"))?.ips).toEqual(["2001:db8::2"]);
    expect(result.cnameChain).toContainEqual({ from: "alias.fixture.invalid", to: "real.external.invalid" });
    expect(system4).not.toHaveBeenCalled(); expect(system6).not.toHaveBeenCalled(); expect(systemCname).not.toHaveBeenCalled();
    expect(custom4).toHaveBeenCalledWith("api.fixture.invalid"); expect(custom6).toHaveBeenCalledWith("api.fixture.invalid"); expect(customCname).toHaveBeenCalledWith("api.fixture.invalid");
  });

  it("F05 generates suffix labels once and calibrates permutations against wildcard DNS", async () => {
    vi.spyOn(dns.Resolver.prototype, "resolve4").mockImplementation(async (host: string) => host === "api-dev.fixture.invalid" ? ["192.0.2.2"] : ["192.0.2.1"]);
    vi.spyOn(dns.Resolver.prototype, "resolve6").mockResolvedValue([]);
    vi.spyOn(dns.Resolver.prototype, "resolveCname").mockResolvedValue([]);
    const { alterSubdomains } = await import("../src/domain/subdomainAlter.js");
    const result = await alterSubdomains({ hosts: ["api.fixture.invalid"], domain: "fixture.invalid", nameservers: ["127.0.0.1"], maxCandidates: 20 });
    expect(result.samples).toContain("api-dev.fixture.invalid");
    expect(result.samples.every(h => !/api-[^.]+\.api-/.test(h))).toBe(true);
    expect(result.resolved).toEqual([{ host: "api-dev.fixture.invalid", ips: ["192.0.2.2"] }]);
    expect((result as unknown as { wildcardDns: boolean }).wildcardDns).toBe(true);
  });

  it("F03 does not learn a backup soft404 from disagreeing random bodies", async () => {
    const pool = http(); let n = 0;
    pool.intercept({ path: /.*/ }).reply(options => ({ statusCode: 200, data: String(options.path) === "/entry.php.bak" ? "first" : ++n % 2 ? "first" : "other", responseOptions: { headers: { "content-type": "text/plain" } } })).persist();
    const { findBackups } = await import("../src/domain/backupFind.js");
    const result = await findBackups({ baseUrl: "https://fixture.invalid/a/?x=2", targets: ["entry.php"], maxCandidates: 1, outputRoot: await root() });
    expect(result.found.map(f => new URL(f.url).pathname)).toEqual(["/entry.php.bak"]);
  });

  it("F03 probes independently exposed subpaths and preserves unsupported panel leads", async () => {
    const pool = http();
    pool.intercept({ path: /.*/ }).reply(options => {
      const p = String(options.path);
      const data = p === "/actuator/env" ? '{"propertySources":[{"name":"env"}]}' : p === "/admin" ? "<title>Custom login</title><input type=password>" : "missing";
      return { statusCode: ["/actuator/env", "/admin"].includes(p) ? 200 : 404, data };
    }).persist();
    const { probeAdminSurface } = await import("../src/domain/adminSurface.js");
    const result = await probeAdminSurface({ baseUrl: "https://fixture.invalid", outputRoot: await root() });
    expect(result.found.map(f => new URL(f.url).pathname)).toEqual(["/actuator/env"]);
    expect((result as unknown as { candidates: { url: string; reason: string }[] }).candidates).toContainEqual(expect.objectContaining({ url: "https://fixture.invalid/admin", reason: "product-content-unverified" }));
  });
});
