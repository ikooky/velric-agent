import { writeArtifact } from "./enrich.js";

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
  readonly vulnClass?: string;
  readonly name?: string;
  readonly severity?: string;
  readonly summary?: string;
  readonly poc?: string;
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
