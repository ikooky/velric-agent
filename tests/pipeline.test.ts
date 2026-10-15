import { describe, expect, it } from "vitest";
import { dedupeUrls, classifyUrls } from "../src/domain/urlRefine.js";
import { detectTakeovers } from "../src/domain/subdomains.js";
import { findingsSarif } from "../src/application/report.js";
import { budgetExceeded, huntBegin, huntRecord } from "../src/application/huntDriver.js";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("dedupe_urls (uro-style)", () => {
  it("folds same-path different-value params", () => {
    const r = dedupeUrls({ urls: [
      "https://t.com/a?id=1", "https://t.com/a?id=2", "https://t.com/a?id=999",
      "https://t.com/b?page=1", "https://t.com/b?page=5",
    ] });
    expect(r.kept).toBe(2);
    expect(r.urls).toContain("https://t.com/a?id=1");
    expect(r.urls).toContain("https://t.com/b?page=1");
  });

  it("drops static extensions but honors whitelist", () => {
    const r = dedupeUrls({ urls: ["https://t.com/x.js", "https://t.com/y.php", "https://t.com/z.png"] });
    expect(r.urls.some((u) => u.endsWith(".js"))).toBe(false);
    expect(r.urls.some((u) => u.endsWith(".png"))).toBe(false);
    expect(r.urls.some((u) => u.endsWith(".php"))).toBe(true);
    const r2 = dedupeUrls({ urls: ["https://t.com/x.js"], whitelist: ["js"] });
    expect(r2.urls.some((u) => u.endsWith(".js"))).toBe(true);
  });

  it("fuzzy-normalizes uuid/numeric path segments", () => {
    const r = dedupeUrls({ urls: [
      "https://t.com/users/12345/profile",
      "https://t.com/users/99999/profile",
      "https://t.com/users/3f2a8b1c-1111-2222-3333-444455556666/profile",
    ], fuzzy: true });
    expect(r.kept).toBe(1);
  });

  it("strips tracking params before folding", () => {
    const r = dedupeUrls({ urls: ["https://t.com/p?utm_source=x&id=1", "https://t.com/p?id=1&utm_campaign=y"] });
    expect(r.kept).toBe(1);
  });
});

describe("classify_urls (gf-style)", () => {
  it("tags ssrf/redirect/lfi/xss by param names (multi-class ok)", () => {
    const r = classifyUrls([
      "https://t.com/fetch?url=https://evil",
      "https://t.com/go?next=/home",
      "https://t.com/view?file=index.tpl",
      "https://t.com/search?q=test",
    ]);
    expect(r.byClass["ssrf"]?.some((u) => u.includes("fetch?url"))).toBe(true);
    expect(r.byClass["redirect"]?.some((u) => u.includes("go?next"))).toBe(true);
    expect(r.byClass["lfi"]?.some((u) => u.includes("view?file"))).toBe(true);
    expect(r.byClass["xss"]?.some((u) => u.includes("search?q"))).toBe(true);
  });

  it("tags idor only on numeric-valued id params", () => {
    const r = classifyUrls(["https://t.com/orders?order_id=99881", "https://t.com/orders?order_id=abc"]);
    expect(r.byClass["idor"]?.some((u) => u.includes("99881"))).toBe(true);
    expect(r.byClass["idor"]?.some((u) => u.includes("abc"))).toBe(false);
  });

  it("tags debug by path shape alone", () => {
    const r = classifyUrls(["https://t.com/admin/console", "https://t.com/actuator/env"]);
    expect(r.byClass["debug"]?.length).toBe(2);
  });
});

describe("subdomain takeover fingerprints", () => {
  it("matches dangling cname targets to services", () => {
    const r = detectTakeovers([
      { from: "old.example.com", to: "example.github.io" },
      { from: "shop.example.com", to: "example.herokuapp.com" },
      { from: "api.example.com", to: "internal-elastic.example.com" },
    ], []);
    expect(r.length).toBe(2);
    expect(r[0]!.service).toBe("github_pages");
    expect(r[1]!.service).toBe("heroku");
    expect(r.some((x) => x.cname.includes("internal-elastic"))).toBe(false);
  });
});

describe("SARIF export", () => {
  it("emits valid SARIF 2.1.0 with security-severity properties", () => {
    const sarif = JSON.parse(findingsSarif([
      { id: "f1", name: "admin no auth", vulnClass: "broken_access_control", severity: "high", summary: "/admin reachable anonymously" },
      { id: "f2", name: "aws key in bundle", vulnClass: "info_exposure", severity: "medium", summary: "AKIA key in app.js" },
    ] as never));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].results[0].level).toBe("error");
    expect(sarif.runs[0].results[1].level).toBe("warning");
    expect(sarif.runs[0].results[0].properties["security-severity"]).toBe("7.5");
    expect(sarif.runs[0].tool.driver.rules.some((r: { id: string }) => r.id.startsWith("VELRIC-"))).toBe(true);
  });
});

describe("hunt budget caps", () => {
  it("hard-stops hunt_record past maxRounds", async () => {
    const root = mkdtempSync(join(tmpdir(), "hunt-budget-"));
    await huntBegin({ goal: "test budget", outputRoot: root, maxRounds: 2 });
    // rounds 1..2 pass; round 3 must be refused
    const r1 = await huntRecord({ outputRoot: root, facts: [{ summary: "round 1 fact" }] });
    expect(r1.budgetExceeded).toBeUndefined();
    const r2 = await huntRecord({ outputRoot: root, facts: [{ summary: "round 2 fact" }] });
    expect(r2.budgetExceeded).toBeUndefined();
    const r3 = await huntRecord({ outputRoot: root, facts: [{ summary: "round 3 fact" }] });
    expect(r3.budgetExceeded).toContain("maxRounds");
    expect(r3.accepted).toBe(0);
    // further records also refused (sticky stop)
    const r4 = await huntRecord({ outputRoot: root, facts: [{ summary: "post-stop" }] });
    expect(r4.budgetExceeded).toContain("maxRounds");
  }, 15000);

  it("budgetExceeded computes time/cost caps", () => {
    expect(budgetExceeded({ startedAt: new Date(Date.now() - 10 * 60000).toISOString(), rounds: 1, cost: 0, caps: { maxDurationMin: 5 } })).toContain("maxDurationMin");
    expect(budgetExceeded({ startedAt: new Date().toISOString(), rounds: 1, cost: 9.9, caps: { maxCost: 10 } })).toBeNull();
    expect(budgetExceeded({ startedAt: new Date().toISOString(), rounds: 1, cost: 11, caps: { maxCost: 10 } })).toContain("maxCost");
  });
});
