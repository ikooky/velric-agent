import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

/** Electron asar patcher/repacker. Applies exact (or regex) text substitutions
 *  located by `asar-unpack` findings, rebuilds the archive header with fresh
 *  offsets and writes a drop-in replacement — the actual crack step: flip a
 *  license comparison, point an activation URL at a local server, or delete a
 *  paywall branch. Length changes are fine (offsets are recomputed). */

export interface AsarPatchOp {
  readonly file: string;
  readonly find: string;
  readonly replace: string;
  /** Treat `find` as a regular expression (global). */
  readonly regex?: boolean;
  /** Apply only this match number (1-based, default all). */
  readonly nth?: number;
}

export interface AsarPatchInput {
  readonly asarPath: string;
  /** Where to write the patched archive (default: <asar>.patched.asar). */
  readonly outputPath?: string;
  readonly patches: readonly AsarPatchOp[];
}

export interface AsarPatchApplied {
  readonly file: string;
  readonly find: string;
  readonly matches: number;
  readonly applied: number;
}

export interface AsarPatchResult {
  readonly input: string;
  readonly output: string;
  readonly patchedFiles: number;
  readonly applied: AsarPatchApplied[];
  readonly missing: string[];
  readonly sha256Before: string;
  readonly sha256After: string;
  readonly bytes: number;
}

interface AsarNode { readonly files?: Record<string, AsarNode>; size?: number; offset?: string | number; readonly link?: string }

interface Entry { path: string; size: number; offset: number }

const sha = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

const parse = (raw: Buffer): { header: AsarNode; dataStart: number; entries: Entry[] } => {
  if (raw.length < 12 || raw.readUInt32LE(0) !== 4) throw new Error("not an asar");
  const headerSize = raw.readUInt32LE(4);
  if (headerSize <= 0 || 8 + headerSize > raw.length) throw new Error("bad header size");
  const header = JSON.parse(raw.toString("utf8", 8, 8 + headerSize).replace(/\u0000+$/, "")) as AsarNode;
  const dataStart = 8 + headerSize;
  const entries: Entry[] = [];
  const walk = (node: AsarNode, prefix: string): void => {
    for (const [name, child] of Object.entries(node.files ?? {})) {
      const p = prefix ? `${prefix}/${name}` : name;
      if (child.files) walk(child, p);
      else if (child.size !== undefined && child.offset !== undefined) entries.push({ path: p, size: child.size, offset: Number(child.offset) });
    }
  };
  walk(header, "");
  return { header, dataStart, entries };
};

const fileBytes = (raw: Buffer, dataStart: number, entry: Entry): Buffer => raw.subarray(dataStart + entry.offset, dataStart + entry.offset + entry.size);

export const patchAsar = async (input: AsarPatchInput): Promise<AsarPatchResult> => {
  const raw = await readFile(input.asarPath);
  const { header, dataStart, entries } = parse(raw);
  const missing: string[] = [];
  const applied: AsarPatchApplied[] = [];
  const contents = new Map<string, Buffer>();

  for (const op of input.patches) {
    const entry = entries.find((e) => e.path === op.file);
    if (!entry) { missing.push(op.file); continue; }
    const before = contents.get(op.file) ?? Buffer.from(fileBytes(raw, dataStart, entry));
    const text = before.toString("utf8");
    let count = 0;
    let out = text;
    if (op.regex) {
      const re = new RegExp(op.find, "g");
      count = (text.match(re) ?? []).length;
      out = text.replace(re, op.replace);
    } else {
      count = text.split(op.find).length - 1;
      if (op.nth) {
        let seen = 0;
        out = text.replaceAll(op.find, (m) => { seen++; return seen === op.nth ? op.replace : m; });
      } else {
        out = text.split(op.find).join(op.replace);
      }
    }
    if (count === 0) { missing.push(`${op.file}: ${op.find.slice(0, 40)}`); continue; }
    applied.push({ file: op.file, find: op.find, matches: count, applied: op.nth ? 1 : count });
    contents.set(op.file, Buffer.from(out, "utf8"));
  }
  if (applied.length === 0) throw new Error(`no patch matched (missing: ${missing.join("; ")})`);

  // Rebuild the header with renumbered offsets, preserving node flags unknown
  // to us by mutating the parsed tree in place.
  const order = entries.slice().sort((a, b) => a.path.localeCompare(b.path));
  const blobs: Buffer[] = [];
  let offset = 0;
  const nodeAt = (path: string): (AsarNode & { offset?: string }) | undefined => {
    let node: AsarNode | undefined = header;
    for (const part of path.split("/")) node = node?.files?.[part];
    return node as (AsarNode & { offset?: string }) | undefined;
  };
  for (const e of order) {
    const data = contents.get(e.path) ?? Buffer.from(fileBytes(raw, dataStart, e));
    const node = nodeAt(e.path);
    if (node) { node.size = data.length; node.offset = String(offset); }
    blobs.push(data);
    offset += data.length;
  }
  const headerBuf = Buffer.from(JSON.stringify(header));
  const pad = (4 - (headerBuf.length % 4)) % 4;
  const head = Buffer.alloc(8);
  head.writeUInt32LE(4, 0);
  head.writeUInt32LE(headerBuf.length + pad, 4);
  const out = Buffer.concat([head, headerBuf, Buffer.alloc(pad), ...blobs]);
  const output = input.outputPath ?? input.asarPath.replace(/\.asar$/i, "") + ".patched.asar";
  await writeFile(output, out);

  return {
    input: input.asarPath, output,
    patchedFiles: new Set(applied.map((a) => a.file)).size,
    applied, missing,
    sha256Before: sha(raw), sha256After: sha(out), bytes: out.length,
  };
};
