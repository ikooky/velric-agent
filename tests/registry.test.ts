import { describe, expect, it } from "vitest";
import { ALL_CONTRACTS } from "../src/contracts/contracts.js";
import { handlers } from "../src/server/registerTools.js";

describe("tool registry", () => {
  it("every contract has a handler", () => {
    for (const c of ALL_CONTRACTS) {
      expect(handlers[c.name], `missing handler for ${c.name}`).toBeDefined();
    }
  });
  it("every handler has a contract (no orphans)", () => {
    const names = new Set(ALL_CONTRACTS.map((c) => c.name));
    for (const h of Object.keys(handlers)) {
      expect(names.has(h), `orphan handler: ${h}`).toBe(true);
    }
  });
});
