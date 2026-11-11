import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { writeArtifact } from "../adapters/artifacts.js";

/** Electron .asar unpack + entitlement-check localization. Extracts the app
 *  archive (bounded), maps package identity and update feed, then locates
 *  license/trial/activation logic: local comparisons, remote validation
 *  endpoints, obfuscation level — the exact spots a crack has to touch. */

export interface AsarInput {
  readonly asarPath: string;
  readonly outputRoot: string;
  /** Skip extraction, only list and scan (uses the in-memory archive). */
  readonly listOnly?: boolean;
  /** Per-file extraction cap (default 30 MiB) and total cap (default 200 MiB). */
  readonly maxFileBytes?: number;
  readonly maxTotalBytes?: number;
}

export type LicenseKind = "local-check" | "remote-check" | "references";

export interface LicenseFinding {
  readonly file: string;
  readonly line: number;
  readonly kind: LicenseKind;
  readonly snippet: string;
  readonly endpoint?: string;
}

export interface AsarResult {
  readonly asar: string;
  readonly bytes: number;
  readonly entryCount: number;
  readonly extracted: number;
  readonly skipped: number;
  readonly package: { name?: string; version?: string; main?: string; electron?: string; updateFeed?: string };
  readonly findings: LicenseFinding[];
  readonly obfuscation: "none" | "light" | "heavy";
  readonly extractedRoot?: string;
  readonly artifacts: { path: string; bytes: number }[];
}

interface AsarNode { readonly files?: Record<string, AsarNode>; readonly size?: number; readonly offset?: string | number; readonly link?: string }

const LICENSE_RE = /license[_-]?(?:key|code|token|file)|activation[_-]?(?:key|code|server)|serial[_-]?(?:number|key)|(?:trial|expiry|expire[sd]?)[_-]?(?:date|time|days|period)?|machine[_-]?id|hardware[_-]?id|device[_-]?fingerprint|isLicensed|isActivated|checkLicense|validateLicense/i;
const REMOTE_RE = /["'`](https?:\/\/[^"'`\s]{4,160}\/(?:api\/)?(?:licen[cs]e|activat\w*|validat\w*|subscription\w*|entitlement\w*|verify)[^"'`\s]*)["'`]/i;
const UPDATE_RE = /(setFeedURL|update\.electronjs\.org|app-update\.(?:yml|json)|publish[_-]?provider|generic[_-]?url)/i;
const LOCAL_SIGNALS = /(=|\beq\b|!==|===|crypto|Buffer\.from|btoa|atob|hash|signature|checksum)/;
const SCAN_EXT = /\.(?:js|mjs|cjs|ts|json|html?|vue|svelte)$/i;

const walk = (node: AsarNode, prefix: string, out: { path: string; offset: number; size: number }[]): void => {
  for (const [name, child] of Object.entries(node.files ?? {})) {
    const p = prefix ? `${prefix}/${name}` : name;
    if (child.files) walk(child, p, out);
    else if (child.size !== undefined && child.offset !== undefined) out.push({ path: p, offset: Number(child.offset), size: child.size });
  }
};

/** Safe relative extraction target (archive paths can contain ../). */
const targetPath = (root: string, rel: string): string => {
  const clean = rel.split("/").filter((s) => s && s !== "." && s !== "..").join("/");
  const full = resolve(root, clean);
  if (!full.startsWith(resolve(root))) throw new Error(`path escape: ${rel}`);
  return full;
};

const scanFile = (rel: string, text: string, findings: LicenseFinding[]): void => {
  if (!SCAN_EXT.test(rel)) return;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.length > 2000) continue; // minified single-line: handled by obfuscation stat
    const remote = REMOTE_RE.exec(line);
    const license = LICENSE_RE.exec(line);
    if (!license && !remote) continue;
    const kind: LicenseKind = remote ? "remote-check" : LOCAL_SIGNALS.test(line) ? "local-check" : "references";
    findings.push({ file: rel, line: i + 1, kind, snippet: line.trim().slice(0, 200), endpoint: remote?.[1] });
    if (findings.length >= 200) return;
  }
};

export const unpackAsar = async (input: AsarInput): Promise<AsarResult> => {
  const raw = await readFile(input.asarPath);
  if (raw.length < 12) throw new Error("too small for asar");
  const sizeField = raw.readUInt32LE(0);
  if (sizeField !== 4) throw new Error(`not an asar (leading uint32=${sizeField})`);
  const headerSize = raw.readUInt32LE(4);
  if (headerSize <= 0 || headerSize > 16 * 1024 * 1024 || 8 + headerSize > raw.length) throw new Error(`bad asar header size ${headerSize}`);
  const header = JSON.parse(raw.toString("utf8", 8, 8 + headerSize).replace(/\u0000+$/, "")) as AsarNode;
  const dataStart = 8 + headerSize;
  const entries: { path: string; offset: number; size: number }[] = [];
  walk(header, "", entries);

  const pkgEntry = entries.find((e) => e.path === "package.json");
  let pkg: AsarResult["package"] = {};
  if (pkgEntry && pkgEntry.size <= 512 * 1024) {
    try {
      const doc = JSON.parse(raw.toString("utf8", dataStart + pkgEntry.offset, dataStart + pkgEntry.offset + pkgEntry.size)) as { name?: string; version?: string; main?: string; dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      pkg = { name: doc.name, version: doc.version, main: doc.main, electron: doc.devDependencies?.electron ?? doc.dependencies?.electron };
    } catch { /* corrupt package.json */ }
  }

  const findings: LicenseFinding[] = [];
  let obfuscation: AsarResult["obfuscation"] = "none";
  let minified = 0;
  for (const e of entries) {
    if (e.size > 4 * 1024 * 1024 || !SCAN_EXT.test(e.path)) continue;
    const text = raw.toString("utf8", Math.min(dataStart + e.offset, raw.length), Math.min(dataStart + e.offset + e.size, raw.length));
    if (text.split("\n").some((l) => l.length > 4000)) minified++;
    scanFile(e.path, text, findings);
    if (UPDATE_RE.test(text)) {
      const m = UPDATE_RE.exec(text);
      if (m?.[1] && !pkg.updateFeed) pkg = { ...pkg, updateFeed: m[1] };
    }
    if (findings.length >= 200) break;
  }
  obfuscation = minified > entries.length * 0.3 ? "heavy" : minified > 3 ? "light" : "none";

  let extracted = 0;
  let skipped = 0;
  let extractedRoot: string | undefined;
  if (!input.listOnly) {
    extractedRoot = join(input.outputRoot, "asar");
    const maxFile = input.maxFileBytes ?? 30 * 1024 * 1024;
    let total = 0;
    const maxTotal = input.maxTotalBytes ?? 200 * 1024 * 1024;
    for (const e of entries) {
      if (e.size > maxFile || total + e.size > maxTotal) { skipped++; continue; }
      const dst = targetPath(extractedRoot, e.path);
      await mkdir(dirname(dst), { recursive: true });
      await writeFile(dst, raw.subarray(dataStart + e.offset, dataStart + e.offset + e.size));
      total += e.size;
      extracted++;
    }
  }

  const body = JSON.stringify({ asar: input.asarPath, bytes: raw.length, entryCount: entries.length, extracted, skipped, package: pkg, findings, obfuscation }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "asar.json", body);
  return { asar: input.asarPath, bytes: raw.length, entryCount: entries.length, extracted, skipped, package: pkg, findings, obfuscation, extractedRoot, artifacts: [artifact] };
};
