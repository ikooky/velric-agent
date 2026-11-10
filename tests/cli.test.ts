import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { GROUPS, COMMAND_INDEX, usageText } from "../src/cli/registry.js";

describe("CLI registry alignment", () => {
  it("every group handler is advertised in usage", () => {
    const usage = usageText();
    for (const cmd of COMMAND_INDEX.keys()) {
      expect(usage, `registry dispatches "${cmd}" but usage never mentions it`).toMatch(
        new RegExp(`^\\s+velric-agent ${cmd}\\b`, "m"),
      );
    }
  });
  it("every usage line maps to a registered handler", () => {
    const usageCmds = [...usageText().matchAll(/^\s+velric-agent ([a-z][a-z0-9-]*)/gm)].map((m) => m[1]);
    const unique = [...new Set(usageCmds)].filter((c) => c !== "help");
    expect(unique.length).toBeGreaterThanOrEqual(100);
    for (const cmd of unique) {
      expect(COMMAND_INDEX.has(cmd), `usage advertises "${cmd}" but no handler is registered`).toBe(true);
    }
  });
  it("no command appears in two groups", () => {
    const seen = new Set<string>();
    for (const g of GROUPS) {
      for (const cmd of Object.keys(g.handlers)) {
        expect(seen.has(cmd), `"${cmd}" is claimed by two groups`).toBe(false);
        seen.add(cmd);
      }
    }
    expect(seen.size).toBe(COMMAND_INDEX.size);
  });
  it("no group file was lost in the cli.ts split", async () => {
    // The old monolith had exactly 104 dispatch cases; the registry must carry them all.
    expect(COMMAND_INDEX.size).toBe(104);
    const legacy = await readFile(new URL("../src/cli.ts", import.meta.url), "utf8");
    expect(legacy.trim()).toBe('export { runCli, dispatch } from "./cli/index.js";');
  });
});
