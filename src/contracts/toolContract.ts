import type { z } from "zod";

import type { ToolError } from "../domain/result.js";

/** Caller-visible MCP execution hints (mirrors the SDK's ToolAnnotations). */
export interface ToolAnnotations {
  readonly readOnlyHint: boolean;
  readonly destructiveHint: boolean;
  readonly idempotentHint: boolean;
  readonly openWorldHint: boolean;
}

/** Canonical adapter families responsible for public MCP tools. */
export const TOOL_KINDS = [
  "net",
  "static",
  "runtime",
  "structure",
  "evidence",
  "policy",
] as const;

export type ToolKind = (typeof TOOL_KINDS)[number];

/** One validated example request for an MCP tool contract. */
export interface ToolExample {
  readonly title: string;
  readonly input: Readonly<Record<string, unknown>>;
}

/**
 * Single source of truth for one public MCP tool. The input schema is the
 * caller boundary; the output schema documents the success shape. Every tool is
 * stateless: it reads its arguments, does the work, and (when it produces
 * artifacts) writes them under a caller-supplied output_root. Nothing is
 * retained between calls.
 */
export interface ToolContract<
  Name extends string = string,
  Input extends z.ZodType = z.ZodType,
  Output extends z.ZodType = z.ZodType,
> {
  readonly name: Name;
  readonly title: string;
  readonly description: string;
  readonly kind: ToolKind;
  readonly inputSchema: Input;
  readonly outputSchema: Output;
  readonly annotations: ToolAnnotations;
  readonly examples: readonly ToolExample[];
  /** Who should call this tool. "host" = caller-facing (default);
   *  "internal" = pipeline bookkeeping — registered only in the full
   *  profile (REA-style capability gating keeps the catalog complete while
   *  letting lean hosts see just the recon surface). */
  readonly audience?: "host" | "internal";
}

/** Read-only, non-destructive, closure-safe defaults for a pure probe. */
export const readOnlyAnnotations = (openWorld = true): ToolAnnotations => ({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: openWorld,
});

/** Annotations for a tool that writes files under a caller-supplied path. */
export const writingAnnotations = (openWorld = true): ToolAnnotations => ({
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: openWorld,
});

/** Project a ToolError into the canonical wire shape. */
export const projectToolError = (
  error: ToolError,
): Record<string, unknown> => ({
  error: {
    code: error.code,
    message: error.message,
    ...(error.details === undefined ? {} : { details: error.details }),
    ...(error.remediation === undefined
      ? {}
      : { remediation: error.remediation }),
  },
});