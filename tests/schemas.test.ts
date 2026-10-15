import { describe, expect, it } from "vitest";
import { ALL_CONTRACTS } from "../src/contracts/contracts.js";

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
    { tool: "workflow_guide", sample: "guide text" },
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
