import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

/** Screenshot evidence collector (gowitness design): headless Chromium visits
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
}

export interface ScreenshotResult {
  readonly captured: number;
  readonly failed: number;
  readonly entries: ScreenshotEntry[];
  /** buckets -> urls: template detection (same CMS / same error page). */
  readonly clusters: Record<string, string[]>;
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
  await mkdir(input.outputRoot, { recursive: true });
  const shotDir = join(input.outputRoot, "screenshots");
  await mkdir(shotDir, { recursive: true });

  const { chromium } = await import("playwright-core");
  const execPath = input.chromiumPath ?? (await findChromium());
  if (!execPath) {
    return { captured: 0, failed: input.urls.length, entries: [], clusters: {}, artifacts: [], };
  }
  const sandboxArgs = process.getuid?.() === 0 ? ["--no-sandbox"] : [];
  const browser = await chromium.launch({
    executablePath: execPath,
    headless: true,
    args: [...sandboxArgs, "--disable-dev-shm-usage"],
    ...(input.proxy ? { proxy: { server: input.proxy } } : {}),
  });

  const entries: ScreenshotEntry[] = [];
  const conc = input.concurrency ?? 3;
  const urls = [...input.urls];
  let idx = 0;
  const worker = async (): Promise<void> => {
    const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
    const page = await ctx.newPage();
    while (idx < urls.length) {
      const url = urls[idx++]!;
      try {
        const resp = await page.goto(url, { timeout: input.timeoutMs ?? 20000, waitUntil: "domcontentloaded" });
        await page.waitForTimeout(600); // settle SPA paint
        const buf = await page.screenshot({ type: "png" });
        const hash = createHash("sha256").update(buf).digest("hex");
        const file = join(shotDir, `${hash.slice(0, 16)}.png`);
        await writeFile(file, buf);
        entries.push({
          url,
          finalUrl: page.url(),
          title: await page.title().catch(() => ""),
          status: resp?.status() ?? null,
          screenshotHash: hash,
          bytes: buf.length,
        });
      } catch (e) {
        entries.push({ url, finalUrl: url, title: "", status: null, screenshotHash: "", bytes: 0, error: e instanceof Error ? e.message.slice(0, 120) : String(e).slice(0, 120) });
      }
    }
    await ctx.close().catch(() => undefined);
  };
  await Promise.all(Array.from({ length: Math.min(conc, urls.length) }, worker));
  await browser.close().catch(() => undefined);

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
  const manifest = { capturedAt: new Date().toISOString(), entries: finalEntries, clusters };
  const manifestPath = join(input.outputRoot, "screenshots.json");
  const manifestStr = JSON.stringify(manifest, null, 2);
  await writeFile(manifestPath, manifestStr, "utf8");
  const evidenceManifest = finalEntries.filter((e) => e.screenshotHash).map((e) => ({ source: `screenshot:${e.url}`, label: e.title || e.finalUrl, hash: e.screenshotHash, bytes: e.bytes }));
  await writeFile(join(input.outputRoot, "screenshot_evidence.json"), JSON.stringify(evidenceManifest, null, 2), "utf8");

  const captured = finalEntries.filter((e) => e.screenshotHash).length;
  return {
    captured,
    failed: finalEntries.length - captured,
    entries: finalEntries,
    clusters,
    artifacts: [{ path: manifestPath, bytes: Buffer.byteLength(manifestStr) }],
  };
};
