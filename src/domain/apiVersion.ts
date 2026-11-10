import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** API version-surface drift: same path across version prefixes (v1..v3,
 *  api/, internal/, stable/) probed anonymous vs authenticated — an old
 *  version that dropped an authz layer is a classic silent downgrade. */

export interface VersionInput {
  /** known API path WITH version, e.g. https://x.io/api/v2/users/1 */
  readonly url: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** extra prefixes to test beyond v0..v3 */
  readonly extraPrefixes?: readonly string[];
}
export interface VersionCase {
  readonly url: string;
  readonly version: string;
  readonly anonymousStatus: number;
  readonly authStatus: number;
  readonly anonymousLen: number;
  readonly authLen: number;
  /** anonymous got what auth got (data leak / missing authz) */
  readonly downgradeLeak: boolean;
  readonly bodyPrefix: string;
}
export interface VersionResult {
  readonly probed: number;
  readonly leaks: VersionCase[];
  readonly cases: VersionCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const VERSIONS = ["v0", "v1", "v2", "v3", "v4"];

export const probeApiVersion = async (input: VersionInput): Promise<VersionResult> => {
  const u = new URL(input.url);
  const m = /\/(v\d+|api\/v\d+|internal|stable)\//.exec(u.pathname);
  if (!m) throw new Error("url must contain a version segment like /v2/ or /api/v2/");
  const verSeg = m[1]!;
  const prefix = verSeg.startsWith("api/") ? "api/" : "";
  const verNum = verSeg.replace("api/", "");
  const prefixes = [...new Set([...VERSIONS.map(v => `${prefix}${v}`), ...(input.extraPrefixes ?? [])])];
  const hdrs = { ...(input.headers ?? {}) };
  const authHdrs = { ...hdrs, ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}) };
  const pathAfter = u.pathname.slice(u.pathname.indexOf(verSeg) + verSeg.length);
  const cases: VersionCase[] = [];
  const leaks: VersionCase[] = [];
  for (const p of prefixes) {
    const candidate = new URL(u);
    candidate.pathname = u.pathname.slice(0, u.pathname.indexOf(verSeg)) + p + pathAfter;
    const [anon, auth] = await Promise.allSettled([
      fetchUrl(candidate.toString(), { headers: hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 }),
      input.bearer || input.cookie ? fetchUrl(candidate.toString(), { headers: authHdrs, cookie: input.cookie, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 }) : Promise.resolve(null),
    ]);
    const a = anon.status === "fulfilled" ? anon.value : null;
    const t = auth.status === "fulfilled" ? auth.value : null;
    if (!a) continue;
    const anonStatus = a.status;
    const authStatus = t?.status ?? -1;
    const anonLen = a.bytes;
    const authLen = t?.bytes ?? -1;
    // 匿名2xx拿到与鉴权相同量级数据 = 版本降级泄漏
    const dataLike = a.body.replace(/\s/g, "").length > 10 && !/^(?:ok|okoy|pong|\{\}|\[\]|null|true|false)$/i.test(a.body.trim());
    const similarBody = t ? Math.abs(anonLen - authLen) < Math.max(authLen * 0.05, 64) : dataLike;
    const downgradeLeak = anonStatus >= 200 && anonStatus < 300 && (t ? (authStatus >= 200 && authStatus < 300 && similarBody) : dataLike);
    const c: VersionCase = { url: candidate.toString(), version: p, anonymousStatus: anonStatus, authStatus, anonymousLen: anonLen, authLen, downgradeLeak, bodyPrefix: a.body.slice(0, 80) };
    cases.push(c);
    if (downgradeLeak && p !== verSeg) leaks.push(c);
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "api_version_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "api_version.md", ["# API version drift", "", `probed ${cases.length} version prefixes`, "", ...leaks.map(l => `- **${l.version}** anonymous ${l.anonymousStatus}/${l.anonymousLen}B ≈ authenticated ${l.authStatus}/${l.authLen}B — authorization missing on this version`)].join("\n")),
  ];
  return { probed: cases.length, leaks, cases, artifacts };
};
