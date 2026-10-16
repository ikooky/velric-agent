import { describe, expect, it } from "vitest";
import { renderReport, generateReport, findingsCsv, findingsSarif } from "../src/application/report.js";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
const scratch = process.env.TMPDIR!;
const temp = () => mkdtemp(join(scratch, "pipeline-test-"));
const hash = (v: string) => createHash("sha256").update(v).digest("hex");
describe("pipeline evidence delivery", () => {
  it("a proof-kind string cannot manufacture a confirmed report", () => {
    const md = renderReport({ title: "audit", goal: "scope", generatedAt: new Date(0), assetCounts: {}, findings: [{ name: "candidate", proofKind: "oob_callback" }] });
    expect(md).toContain("确认发现：**0**");
    expect(md).not.toContain("Confirmed by");
    expect(md).toContain("线索：**1**");
  });
  it("persists stable finding IDs, verifies receipt/blob references, and exports source locations only", async () => {
    const root = await temp();
    const body = "private-object-canary";
    const responseHash = hash(body), requestHash = hash("request");
    await mkdir(join(root, "blobs", responseHash.slice(0, 2)), { recursive: true });
    await writeFile(join(root, "blobs", responseHash.slice(0, 2), `${responseHash}.bin`), body);
    await writeFile(join(root, "observation_ledger.json"), JSON.stringify([{ id: "receipt-1", runId: "run-1", url: "https://app.invalid/objects/1", method: "GET", principal: "attacker", requestHash, responseHash, complete: true, status: 200 }]));
    const finding = { name: "object leak", url: "https://app.invalid/objects/1", severity: "high", proofKind: "identity_marker", proof: { kind: "identity_marker", outcome: "confirmed", observationIds: ["receipt-1"], principal: "attacker", requestHash, responseHash, objectOwner: "victim", expectedPolicy: "deny", evidenceHashes: [responseHash], marker: body, markerPrivate: true }, sourceLocation: { uri: "src/objects.ts", line: 12, column: 3 } };
    const r = await generateReport({ outputRoot: root, reportJson: JSON.stringify({ title: "audit", runId: "run-1", findings: [finding, { name: "forged", validated: true, proofKind: "oob_callback" }] }) });
    const saved = JSON.parse(await readFile(join(root, "report.json"), "utf8"));
    expect(saved.findings[0].findingId).toMatch(/^f_[a-f0-9]{32}$/);
    expect(saved.findings.map((f: any) => f.status)).toEqual(["confirmed", "lead"]);
    expect(r).toMatchObject({ counts: { confirmed: 1, lead: 1, fact: 0 } });
    const sarif = JSON.parse(findingsSarif(saved.findings));
    expect(sarif.runs[0].results[0].locations[0].physicalLocation).toEqual({ artifactLocation: { uri: "src/objects.ts" }, region: { startLine: 12, startColumn: 3 } });
    expect(sarif.runs[0].results[0].properties.targetUrl).toBe(finding.url);
    expect(sarif.runs[0].results[0].partialFingerprints["velricFinding/v1"]).toBe(saved.findings[0].findingId);
    expect(JSON.parse(findingsSarif([{ ...finding, sourceLocation: undefined }])).runs[0].results[0].locations).toBeUndefined();
    await generateReport({ outputRoot: root, reportJson: JSON.stringify({ title: "audit", runId: "run-1", findings: [finding] }) });
    expect(JSON.parse(await readFile(join(root, "report.json"), "utf8")).findings[0].findingId).toBe(saved.findings[0].findingId);
    await writeFile(join(root, "blobs", responseHash.slice(0, 2), `${responseHash}.bin`), "tampered");
    await expect(generateReport({ outputRoot: root, reportJson: JSON.stringify({ runId: "run-1", findings: [finding] }) })).rejects.toThrow(/hash|integrity/);
  });
  it("neutralizes spreadsheet formulas and carriage-return cells", () => {
    const csv = findingsCsv([{ id: "=1+1", name: " \t@SUM(1)", summary: "ok\r=evil" }]);
    expect(csv).not.toContain("\r");
    expect(csv).toContain("'=1+1");
    expect(csv).toContain("' \t@SUM(1)");
  });
});
