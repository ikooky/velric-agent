import { writeArtifact } from "../adapters/artifacts.js";

/** Report input shape. */
export interface ReportInput {
  readonly title: string;
  readonly goal: string;
  readonly generatedAt: Date;
  readonly assetCounts: Record<string, number>;
  readonly findings: readonly FindingView[];
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
}

const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, "": 4 };

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
  b.push(`- 确认发现：**${input.findings.length}** 个`);
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
  readonly reportJson: string; // file content: { title, goal, assetCounts, findings[] }
  readonly outputRoot: string;
}

export const generateReport = async (input: GenReportInput): Promise<{
  findings: number;
  artifacts: { path: string; bytes: number }[];
}> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.reportJson);
  } catch (e) {
    throw { code: "bad_input", message: `report json parse failed: ${(e as Error).message}` };
  }
  const r = parsed as Partial<ReportInput>;
  const md = renderReport({
    title: r.title ?? "",
    goal: r.goal ?? "",
    generatedAt: new Date(),
    assetCounts: r.assetCounts ?? {},
    findings: r.findings ?? [],
  });
  const artifacts = [
    await writeArtifact(input.outputRoot, "report.md", md),
  ];
  return { findings: (r.findings ?? []).length, artifacts };
};


// ---------------- export formats (md per-finding / csv / json) ----------------

const csvCell = (v: string): string => /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;

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
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
  for (const f of findings) {
    const id = `VELRIC-${(f.vulnClass ?? f.name ?? "unknown").replace(/[^a-z0-9]+/gi, "_").toUpperCase().slice(0, 40)}`;
    if (!rules.has(id)) rules.set(id, { id, name: f.vulnClass ?? f.name ?? "unknown", shortDescription: { text: f.name ?? f.vulnClass ?? "finding" } });
  }
  const results = [...findings]
    .sort((a, b) => (sevRank[a.severity ?? ""] ?? 9) - (sevRank[b.severity ?? ""] ?? 9))
    .map((f) => {
      const id = `VELRIC-${(f.vulnClass ?? f.name ?? "unknown").replace(/[^a-z0-9]+/gi, "_").toUpperCase().slice(0, 40)}`;
      const url = (f as { url?: string }).url;
      return {
        ruleId: id,
        level: sarifLevel(f.severity),
        message: { text: f.summary ?? f.name ?? "" },
        locations: url
          ? [{ physicalLocation: { locationDisplayString: url } }]
          : undefined,
        properties: {
          "security-severity": String(sarifRank(f.severity)),
          disposition: (f as { disposition?: string }).disposition ?? "pending",
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
  const { writeFile, mkdir } = await import("node:fs/promises");
  const { join } = await import("node:path");
  await mkdir(input.outputRoot, { recursive: true });
  const out: string[] = [];
  if (input.format === "csv") {
    const p = join(input.outputRoot, "findings.csv");
    await writeFile(p, findingsCsv(input.findings), "utf8");
    out.push(p);
  } else if (input.format === "json") {
    const p = join(input.outputRoot, "findings.json");
    await writeFile(p, findingsJson(input.findings), "utf8");
    out.push(p);
  } else if (input.format === "sarif") {
    const p = join(input.outputRoot, "findings.sarif");
    await writeFile(p, findingsSarif(input.findings), "utf8");
    out.push(p);
  } else {
    for (const f of input.findings) {
      const p = join(input.outputRoot, `finding_${String(f.id ?? f.name ?? "x").replace(/[^\w.-]/g, "_")}.md`);
      await writeFile(p, findingMarkdown(f), "utf8");
      out.push(p);
    }
  }
  return out;
};
