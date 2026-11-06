#!/usr/bin/env node

// Single bin: pure CLI dispatch.
const args = process.argv.slice(2);
const { runCli } = await import("../dist/cli.js");
process.exitCode = await runCli(args);
