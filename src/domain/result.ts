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

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });

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

/** Narrowing helpers capped by the transport's practical memory budget. */
export const MAX_INLINE_BYTES = 8 * 1024 * 1024;

export const isJsonObject = (
  value: unknown,
): value is { [key: string]: unknown } =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Truncate a string to a byte budget, appending an explicit marker. */
export const truncate = (text: string, max: number): string =>
  text.length <= max ? text : `${text.slice(0, max)}…[truncated]`;