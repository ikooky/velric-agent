import { COMMAND_INDEX, usageText } from "./registry.js";
import { parseArgs, num, jarr, jobj, jarrObj, resolveProxy, poolState, type Ctx } from "./shared.js";

/** Dispatch one parsed command via the registry; returns the process exit code. */
export const dispatch = async (command: string, positional: readonly string[], flags: Record<string, string | boolean>, out: (v: unknown) => void): Promise<number> => {
  if (command === "help" || command === "--help" || command === "-h") {
    console.log(usageText());
    return 0;
  }
  const handler = COMMAND_INDEX.get(command);
  if (!handler) {
    console.error(`unknown command: ${command}\n`);
    console.log(usageText());
    return 2;
  }
  const ctx: Ctx = { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy, poolState };
  return handler(ctx);
};

export const runCli = async (argv: readonly string[]): Promise<number> => {
  const { command, positional, flags } = parseArgs(argv);
  const out = (v: unknown) => console.log(JSON.stringify(v, null, 2));
  // --run-id (+ optional --observation-ledger-root) binds every network
  // request this process makes into the observation ledger — required when
  // running recon commands inside a hunt context so hunt-record's
  // anti-hallucination gate can verify observed facts.
  const runBody = async (): Promise<number> => {
    if (typeof flags["run-id"] === "string" && flags["run-id"]) {
      const { withExecution } = await import("../core/execution.js");
      return withExecution({
        tool: `cli:${command}`,
        runId: flags["run-id"],
        ledgerRoot: typeof flags["observation-ledger-root"] === "string" ? flags["observation-ledger-root"] : undefined,
      }, () => dispatch(command, positional, flags, out));
    }
    return dispatch(command, positional, flags, out);
  };
  try {
    return await runBody();
  } catch (cause) {
    const e = cause as { code?: string; message?: string };
    console.error(
      JSON.stringify({ error: { code: e.code ?? "internal_error", message: e.message ?? String(cause) } }, null, 2),
    );
    return 1;
  }
};
