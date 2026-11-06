/**
 * Proof-kind taxonomy (pentest-ai OracleKind discipline): every finding must
 * declare WHICH deterministic mechanism proved it. "An LLM assertion is not a
 * verdict" — same for a raw-string summary. Findings without a proofKind are
 * unproven and render as such; consumers can group/filter by proof strength.
 *
 * Ordered by evidential strength (weakest → strongest).
 */
const PROOF_KINDS = [
  "unproven",
  "static_analysis",
  "reflection_observed",
  "differential",
  "content_hash_migration",
  "identity_marker",
  "server_state",
  "oob_callback",
] as const;

export type ProofKind = (typeof PROOF_KINDS)[number];

/** Fixed verdict→prose table (pentest-ai diff_builder): wording is written
 *  ONCE, in code, per proof kind × outcome — modules never improvise claims.
 *  Deterministic: the same verdict always renders the same sentence. */
const WORDING: Record<ProofKind, { proved: string; unproved: string }> = {
  unproven: {
    proved: "",
    unproved: "No deterministic proof mechanism recorded for this finding — treat as a lead, not a verdict.",
  },
  static_analysis: {
    proved: "Established by static analysis of recovered source/configuration; not exercised against the live target.",
    unproved: "Static pattern matched but the surrounding context invalidated it.",
  },
  reflection_observed: {
    proved: "Payload value reflected in the response body (echo confirmed, not an error page).",
    unproved: "Reflection could not be reproduced on confirmation round.",
  },
  differential: {
    proved: "Confirmed by response differential: status or content changed between the authorized baseline and the probe, reproduced on replay.",
    unproved: "Differential did not reproduce on the confirmation round (flaky endpoint or transient noise).",
  },
  content_hash_migration: {
    proved: "Confirmed by content-hash migration: identical request context, different body hash, stable across repeats.",
    unproved: "Body hash moved once but did not repeat — per-request noise is the likelier cause.",
  },
  identity_marker: {
    proved: "Confirmed by identity marker: another principal's exclusive canary string appeared in this response body.",
    unproved: "Marker string appears in anonymous baselines too (public content), not principal-specific.",
  },
  server_state: {
    proved: "Confirmed by server-state verification: the resource was re-read after the change and the modified field persisted.",
    unproved: "Write accepted (2xx) but re-read shows no persistence — idempotent no-op or write-behind lag.",
  },
  oob_callback: {
    proved: "Confirmed by out-of-band callback: the target server initiated a network interaction to the unique nonce host.",
    unproved: "No OOB interaction observed within the polling window.",
  },
};

export const proofWording = (kind: ProofKind, proved: boolean): string =>
  proved ? WORDING[kind].proved : WORDING[kind].unproved;

/** Normalize an arbitrary value to a ProofKind (fail-closed to unproven). */
export const coerceProofKind = (v: unknown): ProofKind =>
  typeof v === "string" && (PROOF_KINDS as readonly string[]).includes(v) ? (v as ProofKind) : "unproven";
