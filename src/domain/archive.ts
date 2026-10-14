import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Blocked-page archive recovery ladder: when the live fetch is blocked
 *  (403/429/WAF interstitial), try cheap third-party copies before giving
 *  up — Wayback availability API, then archive.today domain rotation. */

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

const ARCHIVE_TODAY_HOSTS = ["archive.ph", "archive.md", "archive.li", "archive.is"];

const isBlocked = (status: number, body: string): boolean => {
  if (status === 403 || status === 429 || status === 503) return true;
  if (status === 200 && /just a moment|cf-browser-verification|challenge-platform|attention required/i.test(body)) return true;
  return false;
};

export const recoverUrl = async (input: ArchiveRecoverInput): Promise<ArchiveRecoverResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000 };

  const live = await fetchUrl(input.url, opts);
  if (!isBlocked(live.status, live.body)) {
    return { url: input.url, liveStatus: live.status, blocked: false, recoveredFrom: null, snapshotUrl: null, contentSha256: live.sha256, bytes: live.bytes, artifacts: [] };
  }

  // Ladder 1: Wayback availability API (cheapest, JSON).
  const wb = await fetchUrl(`https://archive.org/wayback/available?url=${encodeURIComponent(input.url)}`, opts);
  if (wb.status === 200) {
    try {
      const j = JSON.parse(wb.body) as { archived_snapshots?: { closest?: { available?: boolean; url?: string } } };
      const snap = j.archived_snapshots?.closest;
      if (snap?.available && snap.url) {
        const page = await fetchUrl(snap.url, opts);
        if (page.status === 200) {
          const path = join(input.outputRoot, "recovered.html");
          await writeFile(path, page.body);
          return {
            url: input.url, liveStatus: live.status, blocked: true,
            recoveredFrom: "wayback", snapshotUrl: snap.url,
            contentSha256: page.sha256, bytes: page.bytes,
            artifacts: [{ path, bytes: page.bytes }],
          };
        }
      }
    } catch { /* malformed */ }
  }

  // Ladder 2: archive.today host rotation.
  for (const host of ARCHIVE_TODAY_HOSTS) {
    const r = await fetchUrl(`https://${host}/${input.url.replace(/^https?:\/\//, "")}`, { ...opts, redirect: "manual" });
    if (r.status === 200 && r.bytes > 500) {
      const path = join(input.outputRoot, "recovered.html");
      await writeFile(path, r.body);
      return {
        url: input.url, liveStatus: live.status, blocked: true,
        recoveredFrom: "archive-today", snapshotUrl: `https://${host}`,
        contentSha256: r.sha256, bytes: r.bytes,
        artifacts: [{ path, bytes: r.bytes }],
      };
    }
    if (r.status === 302 || r.status === 301) continue; // try next mirror
  }

  return { url: input.url, liveStatus: live.status, blocked: true, recoveredFrom: null, snapshotUrl: null, contentSha256: null, bytes: 0, artifacts: [] };
};
