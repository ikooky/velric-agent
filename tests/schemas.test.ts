import { describe, expect, it } from "vitest";
import { ALL_CONTRACTS } from "../src/contracts/contracts.js";
import golden from "./golden_samples.json" with { type: "json" };
import { readFile } from "node:fs/promises";
import { join } from "node:path";
const repoRoot = join(import.meta.dirname, "..");

/** Golden-shape guard: every contract's outputSchema must safely parse a
 *  representative of the handler's REAL return shape. This is the class of
 *  drift that shipped 10 wrong schemas — schema-vs-code, checked centrally. */
describe("output schema shape guards", () => {
  const cases: { tool: string; sample: unknown }[] = [
    { tool: "fingerprint", sample: { baseUrl: "https://x/", waf: ["cloudflare"], methods: { allowed: [], putWorks: false, traceWorks: false }, cookies: [], techHeaders: {} } },
    { tool: "save_evidence", sample: { blobs: [{ hash: "a".repeat(64), bytes: 3 }] } },
    { tool: "auto_recon", sample: { started: true, statusFile: "/tmp/s.json" } },
    { tool: "auto_batch", sample: { started: true, statusFile: "/tmp/s.json" } },
    { tool: "wayback_urls", sample: { urls: ["https://x/a"] } },
    { tool: "nuclei_lite", sample: { matched: [{ id: "e", severity: "high" }] } },
    { tool: "probe_oidc", sample: { found: [{ kind: "oidc", url: "https://x/.well-known/openid-configuration" }] } },
    { tool: "probe_smuggle", sample: { differentials: [{ dimension: "dot", variantStatus: 200 }], probed: 6 } },
    // Previously-drifted shapes (declared numbers where handlers return arrays):
    { tool: "subdomain_enum", sample: { domain: "x.com", crtSh: ["a.x.com"], bruteFound: [{ host: "b.x.com", ips: ["1.2.3.4"] }], wildcardDns: false, total: ["a.x.com"], artifacts: [] } },
    { tool: "port_scan", sample: { host: "x", open: [{ port: 443, service: "https" }], scanned: 67, artifacts: [] } },
    { tool: "dom_sinks", sample: { chains: [{ file: "a.js", source: "loc", sink: "eval", excerpt: "x" }], files: 1, artifacts: [] } },
    { tool: "build_site_map", sample: { apis: ["GET /api/v1/users"], pages: 3, limitations: [] } },
    { tool: "scan_platform", sample: { id: "p1", name: "demo", targets: ["http://x"], createdAt: "t" } },
    { tool: "evidence_bind", sample: { findingId: "f1", version: 1, bindings: [{ id: "b1", hash: "a".repeat(64), role: "proof" }] } },
    { tool: "mine_hidden_params", sample: { probed: 1, endpointResults: [], artifacts: [], skippedRelativeEndpoints: 0 } },
  ];

  it("declared output shapes parse representative handler returns", () => {
    for (const c of cases) {
      const contract = ALL_CONTRACTS.find((x) => x.name === c.tool);
      expect(contract, `contract ${c.tool} missing`).toBeTruthy();
      const parsed = contract!.outputSchema.safeParse(c.sample);
      expect(parsed.success, `${c.tool}: outputSchema rejects the real return shape — ${JSON.stringify(parsed.success ? null : parsed.error.issues?.slice(0, 2))}`).toBe(true);
    }
  });

  it("every advertised tool has a representative sample (bidirectional)", () => {
    // Advertised → sample: a contract with no sample means its output shape is
    // never validated — the "10 wrong schemas" drift class re-ships silently.
    // Golden samples are REAL handler returns (scripts/generate-golden-samples.mjs
    // invokes every handler against a local mock) — hand-written samples are
    // self-deception and forbidden.
    const missing = ALL_CONTRACTS.filter((c) => !cases.some((s) => s.tool === c.name) && !(c.name in golden.excluded) && !(c.name in golden.samples));
    expect(missing.map((c) => c.name)).toEqual([]);
    // Sample → advertised: a sample naming a retired/renamed tool is asserting
    // a dead surface (registry drift).
    const dead = cases.filter((s) => !ALL_CONTRACTS.some((c) => c.name === s.tool));
    expect(dead.map((s) => s.tool)).toEqual([]);
    // Every exclusion must carry a reason — no free-pass dumping ground.
    for (const [name, reason] of Object.entries(golden.excluded)) {
      expect(String(reason).length, `exclusion ${name} must justify itself`).toBeGreaterThan(10);
      expect(ALL_CONTRACTS.some((c) => c.name === name), `exclusion ${name} names a nonexistent tool`).toBe(true);
    }
  });

  it("golden samples: every REAL handler return parses its declared outputSchema", () => {
    for (const [tool, sample] of Object.entries(golden.samples)) {
      const contract = ALL_CONTRACTS.find((x) => x.name === tool);
      expect(contract, `golden sample for unknown tool ${tool}`).toBeTruthy();
      const parsed = contract!.outputSchema.safeParse(sample);
      expect(parsed.success, `${tool}: outputSchema rejects the REAL handler return — ${JSON.stringify(parsed.success ? null : parsed.error.issues?.slice(0, 2))}`).toBe(true);
    }
  });

  it("chains.json references only live tool names (catalog-complete guard)", async () => {
    const chains = JSON.parse(await readFile(join(repoRoot, "assets/chains.json"), "utf8")) as {
      chains: { id: string; steps: { tool: string }[] }[];
    };
    expect(chains.chains.length).toBeGreaterThan(5);
    const names = new Set(ALL_CONTRACTS.map((c) => c.name));
    for (const ch of chains.chains) {
      for (const st of ch.steps) {
        expect(names.has(st.tool), `chain ${ch.id} references dead tool ${st.tool}`).toBe(true);
      }
    }
  });

  it("every tool that writes artifacts uses writing annotations", () => {
    for (const contract of ALL_CONTRACTS) {
      const writes = contract.annotations?.readOnlyHint !== true;
      const describesArtifact = /writes? [a-z_-]+\.(json|txt|md|html)/i.test(contract.description);
      if (describesArtifact) {
        expect(contract.annotations?.readOnlyHint, `${contract.name}: description promises artifact writes but annotation claims read-only`).not.toBe(true);
      }
    }
  });
});
