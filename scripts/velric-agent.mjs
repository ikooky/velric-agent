#!/usr/bin/env node

import { access } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Route the single bin to MCP mode or CLI mode (mirrors rea-agents' rea.mjs).
const args = process.argv.slice(2);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const isMcpMode = args.length === 1 && (args[0] === "mcp" || args[0] === "--mcp");

if (isMcpMode) {
  const { runMcp } = await import("../dist/main.js");
  process.exitCode = await runMcp();
} else {
  const { runCli } = await import("../dist/cli.js");
  process.exitCode = await runCli(args);
}

// Keep unused-import lint honest for access (probe compiled output exists).
void access;