import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Binary WS-frame protobuf heuristic decoder: walks varint/tag pairs
 *  (wire types 0-5) and reconstructs a field-number → type table. Works
 *  without a .proto file; output is a candidate schema for private
 *  protocols. Non-proto frames are detected (walk fails early) and
 *  reported as such. */

export interface ProtoDecodeInput {
  /** Hex string (frames from ws_schema raw samples) or base64. */
  readonly data: string;
  readonly encoding?: "hex" | "base64";
  readonly outputRoot: string;
}

export interface ProtoDecodeResult {
  readonly looksLikeProtobuf: boolean;
  readonly fields: { fieldNumber: number; wireType: number; wireTypeName: string; offset: number; bytesLength: number }[];
  readonly consumed: number;
  readonly totalBytes: number;
  readonly artifacts: { path: string; bytes: number }[];
}

const WIRE_NAMES: Record<number, string> = {
  0: "varint",
  1: "64-bit",
  2: "length-delimited",
  5: "32-bit",
};

const readVarint = (buf: Buffer, pos: number): { value: number; newPos: number } | null => {
  let result = 0;
  let shift = 0;
  let p = pos;
  while (p < buf.length && p - pos < 10) {
    const b = buf[p]!;
    result += (b & 0x7f) * 2 ** shift;
    p++;
    if ((b & 0x80) === 0) return { value: result, newPos: p };
    shift += 7;
  }
  return null;
};

export const decodeProtoHeuristic = async (input: ProtoDecodeInput): Promise<ProtoDecodeResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const buf = input.encoding === "base64" || input.encoding === undefined
    ? Buffer.from(input.data, "base64")
    : Buffer.from(input.data, "hex");

  const fields: ProtoDecodeResult["fields"] = [];
  let pos = 0;
  let ok = true;

  while (pos < buf.length) {
    const tag = readVarint(buf, pos);
    if (!tag) { ok = false; break; }
    const fieldNumber = Math.floor(tag.value / 8);
    const wireType = tag.value % 8;
    if (fieldNumber === 0 || fieldNumber > 536870911 || ![0, 1, 2, 5].includes(wireType)) { ok = false; break; }
    const fieldStart = tag.newPos;
    let fieldEnd = fieldStart;
    if (wireType === 0) {
      const v = readVarint(buf, fieldStart);
      if (!v) { ok = false; break; }
      fieldEnd = v.newPos;
    } else if (wireType === 1) {
      fieldEnd = fieldStart + 8;
    } else if (wireType === 5) {
      fieldEnd = fieldStart + 4;
    } else {
      const len = readVarint(buf, fieldStart);
      if (!len || len.value > buf.length - len.newPos) { ok = false; break; }
      fieldEnd = len.newPos + len.value;
    }
    if (fieldEnd > buf.length) { ok = false; break; }
    fields.push({ fieldNumber, wireType, wireTypeName: WIRE_NAMES[wireType] ?? "?", offset: pos, bytesLength: fieldEnd - pos });
    pos = fieldEnd;
  }

  // Heuristic acceptance: full walk OR >=80% of bytes consumed with
  // multiple fields (trailing padding/checksums are common in real frames).
  const consumedPct = pos / Math.max(1, buf.length);
  const looksLikeProtobuf = fields.length > 0 && (ok || consumedPct >= 0.8);
  const result: ProtoDecodeResult = {
    looksLikeProtobuf,
    fields,
    consumed: pos,
    totalBytes: buf.length,
    artifacts: [],
  };
  const body = JSON.stringify(result, null, 2);
  const path = join(input.outputRoot, "proto_decode.json");
  await writeFile(path, body);
  result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
  return result;
};
