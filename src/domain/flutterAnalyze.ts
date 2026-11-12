import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { writeArtifact } from "../adapters/artifacts.js";
import { unzipSync } from "fflate";

/** Flutter app static analysis: unzip the APK, pull libapp.so/libflutter.so,
 *  harvest every API domain / route / key-shaped string from the Dart AOT
 *  snapshot, and fingerprint the Dart SDK version. Deep disassembly is
 *  delegated to an external Dart-snapshot tool when --disassembler is given;
 *  the pure-TS layer stays dependency-free. */

export interface FlutterInput {
  readonly apkOrSo: string;
  readonly outputRoot: string;
  /** External Dart AOT disassembler invoked as `TOOL <libdir> <outdir>`; when
   *  omitted only the static layer runs. */
  readonly disassembler?: string;
  readonly maxStrings?: number;
}

export interface FlutterFinding {
  readonly kind: "domain" | "url" | "route" | "key" | "dart-class" | "version";
  readonly value: string;
  readonly where: string;
}

export interface FlutterResult {
  readonly input: string;
  readonly libappBytes: number;
  readonly dartVersion?: string;
  readonly findings: FlutterFinding[];
  readonly counts: Record<string, number>;
  readonly disasm?: { readonly ok: boolean; readonly note: string };
  readonly artifacts: { path: string; bytes: number }[];
}

const DOMAIN_RE = /\b(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.){1,3}(?:com|cn|net|org|io|tv|cc|app|me|cloud|xyz|pro|top|fun|icu)\b(?:\/[a-zA-Z0-9_./-]*)?/g;
const ROUTE_RE = /\/(?:api|app|v\d|rest|officialWebsite|media|vid|mine|user|auth|login|pay|order|buy|vip|checkin)\/[a-zA-Z0-9_/.-]*/g;
const KEY_RE = /(?:interfaceKey|imgKey|signKey|secretKey|appSecret|apiKey|api_key|hmacKey|sign_algorithm)\s*[=:]\s*["']([A-Za-z0-9_-]{8,64})["']/g;
// Dart static string const assignments inside the snapshot: o.key="..."
const STATIC_KEY_RE = /(?:interfaceKey|imgKey|eventSignKey|signKey)\s*=\s*["']([A-Za-z0-9_./+-]{8,80})["']/g;
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const DART_CLASS_RE = /package:([a-z0-9_]+)\/([a-zA-Z0-9_/.]+\.dart)/g;
const VERSION_RE = /Dart version:[\s]*([\d.]+)|dart-lang[\/]sdk@v?([\d.]+)/;

const KEY_HINT = /(passw|secret|token|key|sign|credential)/i;

const printableRuns = (buf: Buffer, minLen: number, cap: number): string[] => {
  const out: string[] = [];
  let start = -1;
  for (let i = 0; i <= buf.length && out.length < cap; i++) {
    const b = i < buf.length ? buf[i]! : 0;
    const printable = b >= 0x20 && b < 0x7f;
    if (printable && start < 0) start = i;
    else if (!printable && start >= 0) {
      if (i - start >= minLen) out.push(buf.toString("latin1", start, i));
      start = -1;
    }
  }
  return out;
};

const runTool = (cmd: string, args: string[]): Promise<{ ok: boolean; note: string }> => new Promise((resolve) => {
  const p = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  p.stderr.on("data", (c) => { err += c; });
  p.on("error", (e) => resolve({ ok: false, note: `spawn failed: ${e.message}` }));
  p.on("close", (code) => resolve({ ok: code === 0, note: code === 0 ? "external disassembler exited 0" : `exit ${code}${err ? `: ${err.slice(0, 120)}` : ""}` }));
  setTimeout(() => { p.kill("SIGKILL"); }, 15 * 60_000);
});

export const analyzeFlutter = async (input: FlutterInput): Promise<FlutterResult> => {
  const raw = await readFile(input.apkOrSo);
  const cap = input.maxStrings ?? 400_000;
  let libapp: Buffer | null = null;
  let libflutter: Buffer | null = null;
  if (raw[0] === 0x50 && raw[1] === 0x4b) {
    // APK (zip): pull arm64 libapp/libflutter, fall back to first arch found.
    const files = unzipSync(raw, { filter: (f) => /^lib\/[^/]+\/(libapp|libflutter)\.so$/.test(f.name) });
    const entries = Object.entries(files);
    const pick = (name: string): Buffer | null => {
      const hits = entries.filter(([p]) => p.endsWith(`/${name}.so`));
      hits.sort((a, b) => (a[0].includes("arm64") ? -1 : 1) - (b[0].includes("arm64") ? -1 : 1));
      return hits[0] ? Buffer.from(hits[0][1]) : null;
    };
    libapp = pick("libapp");
    libflutter = pick("libflutter");
  } else if (input.apkOrSo.endsWith(".so")) {
    libapp = raw;
  }
  if (!libapp) throw new Error("no libapp.so found in input");

  const strings = printableRuns(libapp, 6, cap);
  const joined = strings.join("\n");
  const findings: FlutterFinding[] = [];
  const seen = new Set<string>();
  const push = (kind: FlutterFinding["kind"], value: string, where: string): void => {
    const k = `${kind}:${value}`;
    if (seen.has(k) || value.length > 200) return;
    seen.add(k);
    findings.push({ kind, value, where });
  };

  for (const m of joined.matchAll(DOMAIN_RE)) {
    const v = m[0];
    if (/w3\.org|schema\.org|example\.|invalid|localhost|gnu\.org/i.test(v)) continue;
    push("domain", v, "libapp");
  }
  for (const m of joined.matchAll(ROUTE_RE)) push("route", m[0], "libapp");
  for (const m of joined.matchAll(STATIC_KEY_RE)) push("key", `${m[1]}`, `libapp:${m[0].slice(0, 30)}`);
  for (const m of joined.matchAll(KEY_RE)) push("key", m[1] ?? "", `libapp:${(m[0] ?? "").slice(0, 30)}`);
  for (const m of joined.matchAll(JWT_RE)) push("key", `${m[0].slice(0, 40)}…`, "libapp:jwt");
  const classes = new Set<string>();
  for (const m of joined.matchAll(DART_CLASS_RE)) classes.add(`${m[1]}/${m[2]}`);
  for (const c of [...classes].slice(0, 400)) push("dart-class", c, "libapp");
  const ver = VERSION_RE.exec(libflutter ? printableRuns(libflutter, 8, 50_000).join("\n") : "") ?? VERSION_RE.exec(joined);
  if (ver) {
    const version = ver[1] ?? ver[2] ?? "";
    if (version) { push("version", version, "libflutter"); }
  }
  // Key-shaped static consts: high-entropy runs (hex32 / mixed alnum 16-64)
  // adjacent to sign/key identifiers inside the run stream.
  let prev = "";
  for (const s of strings) {
    try {
      // Bare hex32 with no sign-ish neighbour still matters (Dart symbol pools
      // scatter identifier and value); mask constants (ff.. / 3f.. / 00..) are
      // excluded. Tagged with the neighbour for triage.
      if (/^[0-9a-f]{32}$/.test(s) && !/^(ff|3f|00|7f)/.test(s)) { push("key", s, `libapp:hex32@${prev.slice(0, 16)}`); }
      else if (s.length >= 16 && s.length <= 64 && /^[A-Za-z0-9_.-]+$/.test(s) && /[A-Z]/.test(s) && /[0-9]/.test(s) && /[a-z]/.test(s)
        && (prev === "interfaceKey" || prev === "imgKey" || prev === "signKey" || prev === "eventSignKey")) { push("key", s, `libapp:${prev}`); }
    } finally { prev = s; }
  }

  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.kind] = (counts[f.kind] ?? 0) + 1;

  let disasm: FlutterResult["disasm"];
  if (input.disassembler) {
    // External tool contract: TOOL <dir-with-libapp+libflutter> <outdir>
    const { dirname, join } = await import("node:path");
    const { mkdir, writeFile } = await import("node:fs/promises");
    const libDir = join(input.outputRoot, "libs");
    await mkdir(libDir, { recursive: true });
    await writeFile(join(libDir, "libapp.so"), libapp);
    if (libflutter) await writeFile(join(libDir, "libflutter.so"), libflutter);
    disasm = await runTool(input.disassembler, [libDir, join(input.outputRoot, "dart")]);
  }

  const body = JSON.stringify({ input: input.apkOrSo, libappBytes: libapp.length, dartVersion: ver?.[1] ?? ver?.[2], findings, counts, disasm }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "flutter.json", body);
  return { input: input.apkOrSo, libappBytes: libapp.length, dartVersion: ver?.[1] ?? ver?.[2], findings, counts, disasm, artifacts: [artifact] };
};
