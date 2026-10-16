import type {
  CallToolResult,
  McpServer,
} from "@modelcontextprotocol/server";

import type { ToolContract } from "../contracts/toolContract.js";
import { projectToolError } from "../contracts/toolContract.js";
import type { ToolError } from "../domain/result.js";
import { MAX_INLINE_BYTES } from "../domain/result.js";

/**
 * Serialize a successful value into an MCP tool result. Values that would
 * exceed the transport budget are reported as a resource_constraint error that
 * names the boundary instead of being silently truncated.
 */
const successResult = (value: unknown): CallToolResult => {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2) ?? "null";
  } catch (cause) {
    return errorResult({
      code: "serialization_failed",
      message: "result could not be serialized to JSON",
      details: { cause: String(cause) },
    });
  }
  if (text.length > MAX_INLINE_BYTES) {
    return errorResult({
      code: "resource_constraint",
      message:
        "the operation completed, but its complete response exceeds the inline transport budget",
      details: { response_bytes_at_least: text.length },
      remediation:
        "narrow the request (smaller limit / single page), or write artifacts to output_root and read them locally",
    });
  }
  return {
    content: [{ type: "text", text }],
    structuredContent: value as Record<string, unknown>,
  };
};

/** Serialize a structured failure; errors reach the wire as text only. */
const errorResult = (error: ToolError): CallToolResult => {
  const projected = projectToolError(error);
  return {
    content: [{ type: "text", text: JSON.stringify(projected, null, 2) }],
    isError: true,
  };
};

/** Run one contract's handler and deliver a schema-shaped tool result. */
export const deliver = async (
  contract: ToolContract,
  run: () => Promise<unknown>,
): Promise<CallToolResult> => {
  try {
    const value = await run();
    // Output validation: a mismatch against the contract's outputSchema is a
    // structured contract_violation error naming the offending tool — schema
    // drift must never ship silently.
    const parsed = contract.outputSchema.safeParse(value);
    if (!parsed.success) {
      return errorResult({
        code: "contract_violation",
        message: `tool output failed its declared outputSchema: ${contract.name}`,
        details: {
          issues: parsed.error.issues.slice(0, 8).map((i) => ({ path: i.path.join("."), message: i.message })),
        },
        remediation: "the tool and its contract have drifted — report this to the toolset maintainer",
      });
    }
    // A01: validation is a GATE, not a projector — the handler's original
    // value is delivered; parsed.data would silently strip every field the
    // summary-shaped outputSchema forgot to declare.
    return successResult(value);
  } catch (cause) {
    const error =
      cause !== null &&
      typeof cause === "object" &&
      "code" in cause &&
      "message" in cause
        ? (cause as ToolError)
        : {
            code: "internal_error",
            message: cause instanceof Error ? cause.message : String(cause),
          };
    return errorResult(error);
  }
};