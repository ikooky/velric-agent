import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { createHash } from "node:crypto";
import { EvidenceStore } from "./graphs.js";
import { withRootLock } from "../core/storage.js";
import { writeOwnedManifest } from "../application/harvest.js";

/** Screenshot evidence collector: headless Chromium visits
 *  each URL, captures a PNG + page fingerprint (title / final URL / tech
 *  headers), groups pages by visual-hash similarity (template clustering —
 *  dozens of hosts on the same CMS collapse to one look), and records every
 *  PNG into the evidence blob store (sha256-addressed).
 *
 *  Difference from runtime capture: runtime records API traffic; this
 *  records WHAT THE PAGE LOOKS LIKE — login walls, error pages, admin
 *  panels, default installs — the evidence a human triages first. */

export interface ScreenshotInput {
  readonly urls: readonly string[];
  readonly outputRoot: string;
  readonly chromiumPath?: string;
  /** max parallel pages. default 3. */
  readonly concurrency?: number;
  readonly timeoutMs?: number;
  /** cluster visually-similar pages (dhash-style bucketing). default true. */
  readonly cluster?: boolean;
  readonly proxy?: string;
}

export interface ScreenshotEntry {
  readonly url: string;
  readonly finalUrl: string;
  readonly title: string;
  readonly status: number | null;
  readonly screenshotHash: string;
  readonly bytes: number;
  /** cluster bucket: identical/blank pages share a bucket id. */
  readonly cluster?: string;
  readonly error?: string;
  readonly evidenceHash?: string;
  readonly evidenceStored?: boolean;
  readonly evidenceError?: string;
}

export interface ScreenshotResult {
  readonly captured: number;
  readonly failed: number;
  readonly entries: ScreenshotEntry[];
  /** buckets -> urls: template detection (same CMS / same error page). */
  readonly clusters: Record<string, string[]>;
  readonly clusterMethod: "exact-sha256";
  readonly artifacts: { path: string; bytes: number }[];
}

const findChromium = async (): Promise<string | null> => {
  const { access } = await import("node:fs/promises").then((m) => m);
  const candidates = [
    process.env.VELRIC_CHROMIUM, process.env.CHROMIUM,
    "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable", "/usr/local/bin/chromium",
  ].filter((x): x is string => typeof x === "string" && x.length > 0);
  for (const c of candidates) {
    try { await access(c); return c; } catch { /* next */ }
  }
  return null;
};

export const captureScreenshots = async (input: ScreenshotInput): Promise<ScreenshotResult> => {
  await ensureDir(input.outputRoot);
  await ensureDir(input.outputRoot + "/screenshots");

  const { chromium } = await import("playwright-core");
  const execPath = input.chromiumPath ?? (await findChromium());
  if (!execPath) {
    const entries: ScreenshotEntry[] = input.urls.map(url => ({url,finalUrl:url,title:'',status:null,screenshotHash:'',bytes:0,error:'chromium_not_found'}));
    const artifacts = [await writeArtifact(input.outputRoot, 'screenshots.json', JSON.stringify({entries,clusters:{},clusterMethod:'exact-sha256'})), await writeArtifact(input.outputRoot, 'screenshot_evidence.json', '[]')];
    return { captured: 0, failed: input.urls.length, entries, clusters: {}, clusterMethod: 'exact-sha256', artifacts };
  }
  const sandboxArgs = process.getuid?.() === 0 ? ["--no-sandbox"] : [];
  const browser = await chromium.launch({
    executablePath: execPath,
    headless: true,
    args: [...sandboxArgs, "--disable-dev-shm-usage"],
    ...(input.proxy ? { proxy: { server: input.proxy } } : {}),
  });

  const entries: ScreenshotEntry[] = [];
  const artifacts: {path:string;bytes:number}[] = [];
  const conc = Math.max(1, Math.min(10, input.concurrency ?? 3));
  const urls = [...input.urls];
  let idx = 0;
  const worker = async (): Promise<void> => {
      while (idx < urls.length) {
        const url = urls[idx++]!;
        let ctx: import('playwright-core').BrowserContext | undefined;
        try {
          ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
          const page = await ctx.newPage();
          const resp = await page.goto(url, { timeout: input.timeoutMs ?? 20000, waitUntil: "domcontentloaded" });
          await page.waitForTimeout(600); // settle SPA paint
          const buf = await page.screenshot({ type: "png" });
          const hash = createHash("sha256").update(buf).digest("hex");
          artifacts.push(await writeArtifact(input.outputRoot, `screenshots/${hash}.png`, buf));
          let evidenceHash: string | undefined, evidenceError: string | undefined;
          try {
            await withRootLock(input.outputRoot, async () => {
              const store = new EvidenceStore(input.outputRoot); await store.load();
              const blob = await store.put(buf, `screenshot:${url}`); await store.save();
              const actual = await store.get(blob.hash);
              if (!actual || actual.length !== buf.length || !actual.equals(buf)) throw new Error('PNG evidence read-back mismatch');
              evidenceHash = blob.hash;
            });
          } catch (err) { evidenceError = String(err); }
          entries.push({
            url,
            finalUrl: page.url(),
            title: await page.title().catch(() => ""),
            status: resp?.status() ?? null,
            screenshotHash: hash,
            bytes: buf.length,
            evidenceHash, evidenceStored: !!evidenceHash, evidenceError,
          });
        } catch (e) {
          entries.push({ url, finalUrl: url, title: "", status: null, screenshotHash: "", bytes: 0, error: e instanceof Error ? e.message.slice(0, 120) : String(e).slice(0, 120) });
        } finally { await ctx?.close().catch(() => undefined); }
      }
  };
  try {
    await Promise.all(Array.from({ length: Math.min(conc, urls.length) }, worker));
  } finally {
    await browser.close().catch(() => undefined);
  }

  // clustering: exact-hash buckets (identical pages: same login/error template)
  const clusters: Record<string, string[]> = {};
  const withCluster: ScreenshotEntry[] = [];
  if (input.cluster ?? true) {
    for (const e of entries) {
      if (!e.screenshotHash) continue;
      const bucket = e.screenshotHash.slice(0, 16);
      withCluster.push({ ...e, cluster: bucket });
      (clusters[bucket] ??= []).push(e.url);
    }
  }
  const finalEntries = withCluster.length > 0 ? entries.map((e) => withCluster.find((w) => w.url === e.url && w.screenshotHash === e.screenshotHash) ?? e) : entries;

  // manifest + evidence manifest entry (sha256 blob store compatible)
  const manifest = { capturedAt: new Date().toISOString(), entries: finalEntries, clusters, clusterMethod: 'exact-sha256' };
  const manifestStr = JSON.stringify(manifest, null, 2);
  const artM = await writeArtifact(input.outputRoot, "screenshots.json", manifestStr);
  const evidenceManifest = finalEntries.filter((e) => e.evidenceStored).map((e) => ({ source: `screenshot:${e.url}`, label: e.title || e.finalUrl, hash: e.evidenceHash, bytes: e.bytes }));
  const artE = await writeArtifact(input.outputRoot, "screenshot_evidence.json", JSON.stringify(evidenceManifest, null, 2));
  artifacts.push(artM, artE);
  artifacts.push(await writeOwnedManifest(input.outputRoot, 'screenshot_manifest.json', 'screenshots', input.urls[0] ?? 'about:blank', artifacts, finalEntries.filter(e => e.screenshotHash).length));

  const captured = finalEntries.filter((e) => e.screenshotHash).length;
  return {
    captured,
    failed: finalEntries.length - captured,
    entries: finalEntries,
    clusters,
    clusterMethod: 'exact-sha256',
    artifacts,
  };
};
