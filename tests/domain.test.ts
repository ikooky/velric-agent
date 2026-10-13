import { describe, expect, it } from "vitest";

import { classifyPaths, extractPathLiterals, extractRoutes } from "../src/domain/endpoints.js";
import { chunkUrls } from "../src/domain/chunks.js";
import { buildPermTree, parseUserRouteAuth, DEFAULT_PERM_HEURISTICS } from "../src/domain/permTree.js";
import { mergeParams } from "../src/domain/params.js";
import { buildPreloadScript, DEFAULT_HOOK_CONFIG } from "../src/domain/preload.js";

describe("endpoints", () => {
  it("classifies api vs other paths", () => {
    const js = `fetch("/api/user/list"); get('/rest/x'); nav("/dashboard/main"); href("/logo.png")`;
    const c = classifyPaths(extractPathLiterals(js));
    expect(c.api).toContain("/api/user/list");
    expect(c.api).toContain("/rest/x");
    expect(c.other).toContain("/dashboard/main");
    expect(c.api).not.toContain("/logo.png");
    // single-slash shallow paths without an API hint are dropped (ported behavior)
    const shallow = classifyPaths(extractPathLiterals(`go("/dashboard")`));
    expect(shallow.other).not.toContain("/dashboard");
  });

  it("extracts router routes", () => {
    const js = `{path:"/home",to:"/about",redirect:"/login",href:"/a.png"}`;
    expect(extractRoutes(js)).toContain("/home");
    expect(extractRoutes(js)).toContain("/about");
    // /login excluded? redirect:'/login' IS a route — included; asset href excluded
    expect(extractRoutes(js)).not.toContain("/a.png");
  });
});

describe("chunks", () => {
  it("reconstructs webpack chunk urls", () => {
    const base = "https://target/";
    const js = `.p="/static/";({...})}={1:"abcdef012345",2:"fedcba543210"}[e]+".js"`;
    const urls = chunkUrls(base, js);
    expect(urls.some((u) => u.includes("/static/1.abcdef012345.js"))).toBe(true);
  });

  it("reconstructs vite asset urls", () => {
    const urls = chunkUrls("https://target/", `"assets/index-B2Kx.js"`);
    expect(urls.some((u) => u.endsWith("/assets/index-B2Kx.js"))).toBe(true);
  });
});

describe("permTree", () => {
  it("parses userRouteAuth and builds a tree", () => {
    const js = `userRouteAuth={MONITOR:{url:"/monitor"},MONITOR_ALERT:{url:"/alert"},THREAT:{url:o.THREAT}}`;
    const entries = parseUserRouteAuth(js, {});
    expect(Object.keys(entries)).toContain("MONITOR");
    const tree = buildPermTree(entries, DEFAULT_PERM_HEURISTICS);
    expect(tree.length).toBeGreaterThan(0);
    const monitor = tree.find((n) => n.code === "MONITOR");
    expect(monitor?.children?.map((c) => c.code)).toContain("MONITOR_ALERT");
  });
});

describe("params", () => {
  it("merges samples with confidence", () => {
    const merged = mergeParams([
      { method: "POST", url: "/api/user/list?pageSize=10", body: '{"keyword":"a","page":1}' },
      { method: "POST", url: "/api/user/list?pageSize=20", body: '{"keyword":"b","page":2,"status":1}' },
    ]);
    const ep = merged.find((m) => m.path === "/api/user/list");
    expect(ep).toBeDefined();
    const page = ep!.fields.find((f) => f.name === "page");
    const status = ep!.fields.find((f) => f.name === "status");
    expect(page?.confidence).toBe("high"); // in both samples
    expect(status?.confidence).toBe("medium"); // seen once
    expect(ep!.fields.find((f) => f.name === "pageSize")?.in).toBe("query");
  });
});

describe("preload", () => {
  it("emits syntactically valid script", () => {
    const script = buildPreloadScript(DEFAULT_HOOK_CONFIG);
    expect(() => new Function(script)).not.toThrow();
    expect(script).toContain("__API_RECON_PRELOAD__");
  });
});