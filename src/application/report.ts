import { writeArtifact } from "../adapters/artifacts.js";
import { coerceProofKind, proofWording } from "../domain/proofKinds.js";
import { createHash } from "node:crypto";

/** Report input shape. */
export interface ReportInput {
  readonly title: string;
  readonly goal: string;
  readonly generatedAt: Date;
  readonly assetCounts: Record<string, number>;
  readonly findings: readonly FindingView[];
  /** Confirmed finding count (proof-gated); rendered in the summary. */
  readonly confirmedCount?: number;
}

/** Finding view shape. */
export interface FindingView {
  readonly id?: number | string;
  readonly vulnClass?: string;
  readonly name?: string;
  readonly severity?: string;
  readonly summary?: string;
  readonly poc?: string;
  readonly disposition?: "pending" | "fixed";
  readonly evidenceHashes?: string[];
  readonly evidenceVersion?: number;
  /** Which deterministic mechanism proved this finding (proofKinds.ts).
   *  Missing → unproven; the report renders the honest caveat. */
  readonly proofKind?: string;
}

const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, "": 4 };

const proofLine = (f: FindingView): string => {
  const kind = coerceProofKind(f.proofKind);
  return `> proof (${kind}): Unverified mechanism label; treat as a lead, not a verdict.`;
};

const nz = (s: string | undefined, d: string): string =>
  s !== undefined && s.trim() !== "" ? s : d;

/** Renders the deliverable Markdown report. */
export const renderReport = (input: ReportInput): string => {
  const b: string[] = [];
  b.push(`# 渗透测试报告 — ${nz(input.title, "未命名任务")}`);
  b.push("");
  b.push(`- **任务目标**：${nz(input.goal, "（未指定）")}`);
  b.push(`- **生成时间**：${fmt(input.generatedAt)}`);
  b.push("");
  b.push("## 摘要");
  b.push("");
  b.push(`- 确认发现：**${input.confirmedCount ?? 0}** 个`);
  b.push(`- 线索：**${input.findings.length}** 个`);
  b.push(`- 资产：${Object.entries(input.assetCounts)
    .map(([t, n]) => `${t} ${n}`)
    .join("、") || "无"}`);
  b.push("");
  b.push("## 发现");
  b.push("");
  if (input.findings.length === 0) {
    b.push("_本次未确认漏洞。_");
    b.push("");
  } else {
    const fs = [...input.findings].sort(
      (x, y) => (sevRank[x.severity ?? ""] ?? 9) - (sevRank[y.severity ?? ""] ?? 9),
    );
    let i = 0;
    for (const f of fs) {
      i += 1;
      b.push(`### ${i}. [${(nz(f.severity, "info")).toUpperCase()}] ${nz(f.name, nz(f.vulnClass, "未分类"))}`);
      b.push("");
      b.push(nz(f.summary, ""));
      b.push(proofLine(f));
      b.push("");
      if (f.poc && f.poc.trim() !== "") {
        b.push("**PoC / 证据：**");
        b.push("");
        b.push("```");
        b.push(f.poc);
        b.push("```");
        b.push("");
      }
    }
  }
  return b.join("\n");
};

const fmt = (d: Date): string => {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};

export interface GenReportInput {
  readonly reportJson: string; // file content: { title, goal, assetCounts, findings[], facts? }
  readonly outputRoot: string;
}

/** Receipt reference a finding's proof must be backed by (execution.ts). */
interface ObservationReceipt {
  readonly id: string;
  readonly requestHash: string | null;
  readonly responseHash: string | null;
}

/** Finding-side proof shape (huntDriver-validated findings carry this). */
interface FindingProof {
  readonly kind?: string;
  readonly observationIds?: readonly string[];
  readonly requestHash?: string;
  readonly responseHash?: string;
  readonly evidenceHashes?: readonly string[];
}

export interface PersistedFinding extends FindingView {
  readonly findingId: string;
  readonly status: "confirmed" | "lead";
  readonly url?: string;
  readonly sourceLocation?: { uri: string; line: number; column: number };
  readonly proof?: FindingProof;
}

export interface GenerateReportResult {
  readonly findings: number;
  readonly counts: { confirmed: number; lead: number; fact: number };
  readonly artifacts: { path: string; bytes: number }[];
}

const sha256 = (v: string): string => createHash("sha256").update(v).digest("hex");

/** Stable finding identity: content-addressed (f_ + 32 hex of the finding's
 *  canonical fields). Volatile presentation fields (poc text, disposition)
 *  are excluded so re-generating the report never mints a new id. */
const findingIdFor = (f: FindingView): string => {
  const canonical = JSON.stringify({
    name: f.name ?? null,
    vulnClass: f.vulnClass ?? null,
    severity: f.severity ?? null,
    summary: f.summary ?? null,
    url: (f as { url?: string }).url ?? null,
    proofKind: f.proofKind ?? null,
    proof: (f as { proof?: unknown }).proof ?? null,
    sourceLocation: (f as { sourceLocation?: unknown }).sourceLocation ?? null,
  });
  return `f_${sha256(canonical).slice(0, 32)}`;
};

/** A proof is CONFIRMED only when every observation it cites exists in the
 *  observation ledger with matching request/response digests, and every
 *  referenced evidence blob (finding-level OR proof-level hashes) still
 *  hashes to its address. Anything else is a lead — a proof-kind string
 *  alone can never manufacture a confirmation. */
const proofIsConfirmed = async (
  proof: FindingProof | undefined,
  evidenceHashes: readonly string[] | undefined,
  receipts: readonly ObservationReceipt[],
  outputRoot: string,
): Promise<boolean> => {
  if (!proof || !Array.isArray(proof.observationIds) || proof.observationIds.length === 0) return false;
  for (const id of proof.observationIds) {
    const receipt = receipts.find((r) => r.id === id);
    if (!receipt) return false;
    if (proof.requestHash !== undefined && receipt.requestHash !== proof.requestHash) return false;
    if (proof.responseHash !== undefined && receipt.responseHash !== proof.responseHash) return false;
  }
  const hashes = [...(evidenceHashes ?? []), ...(Array.isArray(proof.evidenceHashes) ? proof.evidenceHashes : [])];
  // Evidence blobs are content-addressed: a missing reference fails
  // verification (finding becomes a lead), but a blob that no longer hashes
  // to its address is TAMPERED evidence — the integrity violation propagates
  // to the caller instead of being silently downgraded.
  const { readBlob } = await import("../core/storage.js");
  const { toolError } = await import("../domain/result.js");
  for (const h of hashes) {
    let blob: Buffer | null;
    try {
      blob = await readBlob(outputRoot, h);
    } catch (cause) {
      const code = (cause as { code?: string }).code;
      if (code === "evidence_integrity" || code === "invalid_hash") {
        const e = toolError("evidence_integrity", `evidence blob ${h} does not match its address: hash integrity check failed`, {
          details: { hash: h },
        });
        throw Object.assign(new Error(e.message), { code: e.code, details: e.details });
      }
      throw cause;
    }
    if (blob === null) return false;
  }
  return true;
};

export const generateReport = async (input: GenReportInput): Promise<GenerateReportResult> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.reportJson);
  } catch (e) {
    throw { code: "bad_input", message: `report json parse failed: ${(e as Error).message}` };
  }
  const r = parsed as Partial<ReportInput> & { facts?: readonly unknown[] };
  const rawFindings = (r.findings ?? []) as readonly (FindingView & Record<string, unknown>)[];

  // Observation ledger lives next to the blobs it references (same root).
  const { readJson } = await import("../core/storage.js");
  const receipts = await readJson<ObservationReceipt[]>(
    input.outputRoot,
    "observation_ledger.json",
    () => [],
    (v) => Array.isArray(v),
  ).catch(() => [] as ObservationReceipt[]);

  const persisted: PersistedFinding[] = [];
  let confirmed = 0;
  for (const f of rawFindings) {
    const id = findingIdFor(f);
    const ok = await proofIsConfirmed(f.proof as FindingProof | undefined, f.evidenceHashes, receipts, input.outputRoot);
    if (ok) confirmed++;
    persisted.push({
      ...f,
      findingId: id,
      status: ok ? "confirmed" : "lead",
    });
  }

  const report = {
    title: r.title ?? "",
    goal: r.goal ?? "",
    runId: (parsed as { runId?: string }).runId ?? null,
    generatedAt: new Date().toISOString(),
    assetCounts: r.assetCounts ?? {},
    counts: { confirmed, lead: persisted.length - confirmed, fact: Array.isArray(r.facts) ? r.facts.length : 0 },
    findings: persisted,
  };
  const { writeJson } = await import("../core/storage.js");
  await writeJson(input.outputRoot, "report.json", report);

  const md = renderReport({
    title: r.title ?? "",
    goal: r.goal ?? "",
    generatedAt: new Date(),
    assetCounts: r.assetCounts ?? {},
    findings: rawFindings,
    confirmedCount: confirmed,
  });
  const artifacts = [
    await writeArtifact(input.outputRoot, "report.md", md),
  ];
  return { findings: persisted.length, counts: report.counts, artifacts };
};


// ---------------- export formats (md per-finding / csv / json) ----------------

/** CSV cell hardening: control characters force quoting; CR is stripped (a
 *  bare CR inside a quoted cell still breaks some parsers); leading
 *  spreadsheet-formula shapes (=,+,-,@, tab-prefixed) get a neutralizing
 *  apostrophe so exported findings cannot execute on open. */
const csvCell = (v: string): string => {
  const noCr = v.replace(/\r\n?/g, "\n");
  // Formula guard after leading whitespace too — " \t@SUM(1)" is a
  // spreadsheet formula cell once the blank prefix is trimmed by Excel.
  const guarded = /^\s*[=+\-@\t]/.test(noCr) ? `'${noCr}` : noCr;
  return /[",\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
};

/** CSV export of a findings batch (velric report/findings.go parity). */
export const findingsCsv = (findings: readonly FindingView[]): string => {
  const head = ["id", "name", "vulnclass", "severity", "disposition", "evidence_version", "summary"];
  const rows = [...findings]
    .sort((a, b) => (sevRank[a.severity ?? ""] ?? 9) - (sevRank[b.severity ?? ""] ?? 9))
    .map((f) => [
      String(f.id ?? ""),
      f.name ?? "",
      f.vulnClass ?? "",
      f.severity,
      (f as { disposition?: string }).disposition ?? "pending",
      String((f as { evidenceVersion?: number }).evidenceVersion ?? 0),
      (f.summary ?? "").replace(/\r?\n/g, " "),
    ]);
  return [head, ...rows].map((r) => r.map((c) => csvCell(String(c ?? ""))).join(",")).join("\n");
};

/** Standalone Markdown for ONE finding (velric per-finding export parity). */
export const findingMarkdown = (f: FindingView): string => {
  const b: string[] = [];
  b.push(`# ${f.name ?? f.vulnClass ?? "未分类"}`);
  b.push("");
  b.push(`- 严重等级：**${f.severity}**`);
  b.push(`- 类别：${f.vulnClass ?? "-"}`);
  b.push(`- 处置状态：${(f as { disposition?: string }).disposition ?? "pending"}`);
  b.push("");
  b.push("## 摘要");
  b.push(f.summary ?? "-");
  b.push("");
  b.push(proofLine(f));
  if (f.poc) {
    b.push("");
    b.push("## PoC");
    b.push("```");
    b.push(f.poc);
    b.push("```");
  }
  const hashes = (f as { evidenceHashes?: string[] }).evidenceHashes ?? [];
  if (hashes.length > 0) {
    b.push("");
    b.push("## 证据");
    for (const h of hashes) b.push(`- sha256:${h}`);
  }
  return b.join("\n");
};

/** JSON export of a findings batch. */
export const findingsJson = (findings: readonly FindingView[]): string =>
  JSON.stringify(
    [...findings].sort((a, b) => (sevRank[a.severity ?? ""] ?? 9) - (sevRank[b.severity ?? ""] ?? 9)),
    null,
    2,
  );

/** SARIF 2.1.0 export (GitHub code scanning compatible): each finding becomes
 *  a result with a security-severity level (CVSS placeholder by rank) on a
 *  synthetic rule per vuln class. */
const sarifLevel = (sev: string | undefined): "none" | "note" | "warning" | "error" => {
  switch (sev) {
    case "critical": case "high": return "error";
    case "medium": case "low": return "warning";
    default: return "note";
  }
};
const sarifRank = (sev: string | undefined): number => {
  switch (sev) {
    case "critical": return 9.0;
    case "high": return 7.5;
    case "medium": return 5.0;
    case "low": return 3.0;
    default: return 1.0;
  }
};

export const findingsSarif = (findings: readonly FindingView[]): string => {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; properties: { "security-severity": string } }>();
  for (const f of findings) {
    const id = `VELRIC-${(f.vulnClass ?? f.name ?? "unknown").replace(/[^a-z0-9]+/gi, "_").toUpperCase().slice(0, 40)}`;
    // GitHub code scanning reads security-severity from the RULE (worst-case
    // wins when multiple findings share a rule id), never from results.
    if (!rules.has(id)) rules.set(id, { id, name: f.vulnClass ?? f.name ?? "unknown", shortDescription: { text: f.name ?? f.vulnClass ?? "finding" }, properties: { "security-severity": String(sarifRank(f.severity)) } });
    else {
      const cur = rules.get(id)!;
      if (sarifRank(f.severity) > Number(cur.properties["security-severity"])) cur.properties["security-severity"] = String(sarifRank(f.severity));
    }
  }
  const results = [...findings]
    .sort((a, b) => (sevRank[a.severity ?? ""] ?? 9) - (sevRank[b.severity ?? ""] ?? 9))
    .map((f) => {
      const id = `VELRIC-${(f.vulnClass ?? f.name ?? "unknown").replace(/[^a-z0-9]+/gi, "_").toUpperCase().slice(0, 40)}`;
      const url = (f as { url?: string }).url;
      // Source locations (recovered source/position) map to SARIF regions;
      // the target URL is a property, never a fake artifact path.
      const sourceLocation = (f as { sourceLocation?: { uri?: unknown; line?: unknown; column?: unknown } }).sourceLocation;
      const location =
        sourceLocation && typeof sourceLocation.uri === "string" && typeof sourceLocation.line === "number" && Number.isInteger(sourceLocation.line) && sourceLocation.line >= 1
          ? {
              physicalLocation: {
                artifactLocation: { uri: sourceLocation.uri },
                region: {
                  startLine: sourceLocation.line,
                  ...(Number.isInteger(sourceLocation.column) ? { startColumn: sourceLocation.column } : {}),
                },
              },
            }
          : undefined;
      const findingId = (f as { findingId?: string }).findingId;
      return {
        ruleId: id,
        level: sarifLevel(f.severity),
        message: { text: f.summary ?? f.name ?? "" },
        ...(location ? { locations: [location] } : {}),
        ...(findingId ? { partialFingerprints: { "velricFinding/v1": findingId } } : {}),
        properties: {
          disposition: (f as { disposition?: string }).disposition ?? "pending",
          ...(url ? { targetUrl: url } : {}),
        },
      };
    });
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "velric-agent", informationUri: "https://github.com/ikooky/velric-agent", rules: [...rules.values()] } },
        results,
      }],
    },
    null,
    2,
  );
};


/** Write findings exports to disk (csv / json / per-finding md / sarif). */
export const generateReportExports = async (input: {
  outputRoot: string;
  format: "csv" | "json" | "md-all" | "sarif";
  findings: readonly FindingView[];
}): Promise<string[]> => {
  const out: string[] = [];
  if (input.format !== "csv" && input.format !== "json" && input.format !== "sarif" && input.format !== "md-all") {
    throw new Error(`unsupported export format: ${JSON.stringify(input.format)}`);
  }
  if (input.format === "csv") {
    const { path: p } = await writeArtifact(input.outputRoot, "findings.csv", findingsCsv(input.findings));
    out.push(p);
  } else if (input.format === "json") {
    const { path: p } = await writeArtifact(input.outputRoot, "findings.json", findingsJson(input.findings));
    out.push(p);
  } else if (input.format === "sarif") {
    const { path: p } = await writeArtifact(input.outputRoot, "findings.sarif", findingsSarif(input.findings));
    out.push(p);
  } else {
    for (const f of input.findings) {
      const { path: p } = await writeArtifact(input.outputRoot, `finding_${String(f.id ?? f.name ?? "x").replace(/[^\w.-]/g, "_")}.md`, findingMarkdown(f));
      out.push(p);
    }
  }
  return out;
};
