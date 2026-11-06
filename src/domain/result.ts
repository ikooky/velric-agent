/** A value that survives JSON serialization. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Result type for operations that can fail with a structured error. */
export type Result<T, E = ToolError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };


/** A structured, actionable tool failure. */
export interface ToolError {
  readonly code: string;
  readonly message: string;
  readonly details?: Record<string, JsonValue>;
  readonly remediation?: string;
}

export const toolError = (
  code: string,
  message: string,
  extras: { details?: Record<string, JsonValue>; remediation?: string } = {},
): ToolError => ({ code, message, ...extras });

