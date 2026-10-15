
import { describe, expect, it } from "vitest";
import { ALL_CONTRACTS } from "../src/contracts/contracts.js";
import { handlers } from "../src/server/registerTools.js";
import { deliver } from "../src/server/delivery.js";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Deliver output-schema enforcement: a valid handler result passes through;
// a drifting result is converted into a structured contract_violation error.
describe("outputSchema enforcement (deliver)", () => {
  it("valid output passes its own outputSchema", async () => {
    const c = ALL_CONTRACTS.find((x) => x.name === "dns_resolve")!;
    const res = await deliver(c, async () => handlers["dns_resolve"]({ hosts: ["localhost"] }));
    expect(res.isError).toBeUndefined();
    const parsed = JSON.parse((res.content as { type: string; text: string }[])[0]!.text);
    expect(parsed.results[0].host).toBe("localhost");
  });

  it("drifting output is rejected as contract_violation, not passed through", async () => {
    const c = ALL_CONTRACTS.find((x) => x.name === "dns_resolve")!;
    // Simulate drift: wrong shape for the declared schema
    const res = await deliver(c, async () => ({ totallyWrongShape: true }));
    expect(res.isError).toBe(true);
    const body = JSON.parse((res.content as { type: string; text: string }[])[0]!.text);
    expect(body.error.code).toBe("contract_violation");
    expect(body.error.message).toContain("dns_resolve");
  });

  it("traffic_record stop-path output validates (stopped/exchanges/note in schema)", async () => {
    const c = ALL_CONTRACTS.find((x) => x.name === "traffic_record")!;
    const root = mkdtempSync(join(tmpdir(), "osd-t-"));
    // stop with no live recorder -> { port: 0, stopped: false, exchanges: 0 }
    const res = await deliver(c, async () => handlers["traffic_record"]({ outputRoot: root, stop: true }));
    expect(res.isError).toBeUndefined();
    const parsed = JSON.parse((res.content as { type: string; text: string }[])[0]!.text);
    expect(parsed.port).toBe(0);
    expect(parsed.stopped).toBe(false);
  });
});
