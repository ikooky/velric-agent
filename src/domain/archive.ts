import { fetchUrl, type FetchResult } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";
import { createHash } from "node:crypto";

export interface ArchiveRecoverInput {
  readonly url: string;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface ArchiveRecoverResult {
  readonly url: string;
  readonly liveStatus: number;
  readonly blocked: boolean;
  readonly recoveredFrom: "wayback" | "archive-today" | null;
  readonly snapshotUrl: string | null;
  readonly contentSha256: string | null;
  readonly bytes: number;
  readonly artifacts: { path: string; bytes: number }[];
}
const MIRRORS = ["archive.ph", "archive.md", "archive.li", "archive.is"];
const challenge = (body: string): boolean => /just a moment|cf-browser-verification|challenge-platform|attention required|captcha|verify (?:you are|that you)|rate limit|snapshot (?:not found|unavailable)|no (?:results|snapshots) found/i.test(body);
const blocked = (status: number, body: string): boolean => [403, 429, 503].includes(status) || status === 200 && challenge(body);
const validPage = (r: FetchResult): boolean => r.status === 200 && r.complete !== false && !r.truncated && !r.error && r.body.trim().length > 0 && !challenge(r.body);
const snapshotFor = (value: string, target: string): string | null => {
  try {
    const u = new URL(value);
    if (!/^https?:$/.test(u.protocol) || u.hostname !== "web.archive.org" || u.username || u.password) return null;
    const original = u.pathname.match(/^\/web\/\d{4,14}(?:[a-z_]+)?\/(https?:\/\/.*)$/i)?.[1];
    return original && new URL(original + u.search).href === new URL(target).href ? u.href : null;
  } catch { return null; }
};
export const recoverUrl = async (input: ArchiveRecoverInput): Promise<ArchiveRecoverResult> => {
  const target = new URL(input.url);
  if (!/^https?:$/.test(target.protocol) || target.username || target.password) throw new Error("invalid archive target");
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, redirect: "manual" as const };
  const live = await fetchUrl(target.href, opts);
  const recoverable = [0, 404, 410].includes(live.status) || blocked(live.status, live.body);
  if (!recoverable) return { url: input.url, liveStatus: live.status, blocked: false, recoveredFrom: null, snapshotUrl: null, contentSha256: live.sha256, bytes: live.bytes, artifacts: [] };
  const saved = async (from: "wayback" | "archive-today", snapshotUrl: string, page: FetchResult): Promise<ArchiveRecoverResult> => {
    const art = await writeArtifact(input.outputRoot, "recovered.html", page.body);
    return { url: input.url, liveStatus: live.status, blocked: true, recoveredFrom: from, snapshotUrl, contentSha256: createHash("sha256").update(page.body).digest("hex"), bytes: art.bytes, artifacts: [art] };
  };
  const wb = await fetchUrl(`https://archive.org/wayback/available?url=${encodeURIComponent(target.href)}`, opts);
  if (wb.status === 200 && wb.complete !== false && !wb.truncated && !wb.error) {
    let snapshot: string | null = null;
    try {
      const data = JSON.parse(wb.body) as { archived_snapshots?: { closest?: { available?: boolean; url?: string } } };
      const closest = data.archived_snapshots?.closest;
      if (closest?.available && typeof closest.url === "string") snapshot = snapshotFor(closest.url, target.href);
    } catch { /* malformed archive response */ }
    if (snapshot) { const page = await fetchUrl(snapshot, opts); if (validPage(page)) return saved("wayback", snapshot, page); }
  }
  for (const host of MIRRORS) {
    const lookup = new URL(`/${target.href}`, `https://${host}`).href;
    const r = await fetchUrl(lookup, opts);
    if (r.complete === false || r.truncated || r.error || challenge(r.body)) continue;
    const links = [r.headers.location, ...[...r.body.matchAll(/(?:href|url)=["']([^"']+)["']/gi)].map(m => m[1])];
    let snapshot: string | null = null;
    for (const link of links) {
      if (!link) continue;
      try {
        const u = new URL(link, lookup);
        if (u.origin === `https://${host}` && /^\/[A-Za-z0-9]{5,12}$/.test(u.pathname) && !u.username && !u.password) { snapshot = u.href; break; }
      } catch { /* unrelated link */ }
    }
    if (!snapshot) continue;
    const page = await fetchUrl(snapshot, opts);
    const mentionsTarget = page.body.includes(target.hostname) || page.headers["x-archive-orig-host"] === target.hostname;
    if (validPage(page) && mentionsTarget) return saved("archive-today", snapshot, page);
  }
  return { url: input.url, liveStatus: live.status, blocked: true, recoveredFrom: null, snapshotUrl: null, contentSha256: null, bytes: 0, artifacts: [] };
};