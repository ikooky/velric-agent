import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.js";

const exec = promisify(execFile);

describe("CLI usage alignment", () => {
  it("every command line in USAGE has a matching case in runCli", async () => {
    const src = await import("node:fs").then((fs) =>
      fs.readFileSync(new URL("../src/cli.ts", import.meta.url), "utf8"),
    );
    const usageCmds = [...src.matchAll(/^\s+velric-agent ([a-z][a-z0-9-]*)/gm)].map((m) => m[1]);
    const unique = [...new Set(usageCmds)].filter((c) => c !== "mcp" && c !== "help");
    expect(unique.length).toBeGreaterThanOrEqual(11);
    for (const cmd of unique) {
      expect(src, `USAGE advertises "${cmd}" but cli.ts has no case for it`).toContain(
        `case "${cmd}"`,
      );
    }
    // Bidirectional: every dispatch case must also be advertised in USAGE —
    // one-way alignment let 7 new commands ship silently unlisted.
    const caseCmds = [...src.matchAll(/^\s+case "([a-z][a-z0-9-]*)":/gm)].map((m) => m[1]);
    const mcpOnly = new Set(["mcp"]);
    for (const cmd of caseCmds) {
      if (mcpOnly.has(cmd)) continue;
      expect(src, `cli.ts dispatches "${cmd}" but USAGE never mentions it`).toMatch(
        new RegExp(`^\\s+velric-agent ${cmd}\\b`, "m"),
      );
    }
  });

  it("help exit code 0 and lists all commands", async () => {
    const { stdout } = await exec("node", ["scripts/velric-agent.mjs", "help"], {
      cwd: process.cwd(),
    });
    for (const c of [
      "dns-resolve",
      "http-probe",
      "harvest",
      "spider",
      "runtime",
      "perm-tree",
      "merge-params",
      "enrich",
      "gen-report",
      "save-evidence",
      "auto",
    ]) {
      expect(stdout).toContain(c);
    }
  });
});
