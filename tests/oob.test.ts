import { describe, expect, it } from "vitest";
import { createOobSession } from "../src/domain/oobConfirm.js";

describe("oob session", () => {
  it("callback host matches server sliding-window contract (20 xid + 13 zbase32)", async () => {
    const client = await createOobSession();
    const cb = client.callbackUrl();
    const label = cb.split(".")[0]!;
    expect(label.length).toBe(33);
    expect(label.slice(0, 20)).toMatch(/^[0-9a-v]+$/);
    expect(label.slice(20)).toMatch(/^[ybndrfg8ejkmcpqxot1uwisza345h769]+$/);
    expect(cb.endsWith(client.session.server)).toBe(true);
  }, 30000);
});
