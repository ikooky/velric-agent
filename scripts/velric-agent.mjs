#!/usr/bin/env node

// Single bin: run the CLI from TypeScript sources directly (Node >= 22.13
// type stripping) — no build step, no dist/ artifact.
const args = process.argv.slice(2);
const module = await import("node:module");
const loaderUrl = new URL("./ts-loader.mjs", import.meta.url);
if (typeof module.registerHooks === "function") {
  const { resolve } = await import(loaderUrl.href);
  module.registerHooks({ resolve });
} else {
  module.register(loaderUrl);
}
const { runCli } = await import("../src/cli.ts");
process.exitCode = await runCli(args);
