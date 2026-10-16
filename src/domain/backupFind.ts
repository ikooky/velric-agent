import { fetchUrl } from "../adapters/http.js";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { join } from "node:path";

/** Backup-file discovery (Wapiti mod_backup-style): probes common backup
 *  suffixes and sibling-dump names for a KNOWN live path — index.php ->
 *  index.php.bak / index.php~ / index.php.old / www.tar.gz... A readable
 *  backup of server code/config is source disclosure by definition.
 *
 *  Downstream: backup-unpack consumes the discovered URLs. Soft-404
 *  calibration (random-path baseline) keeps catch-all routers honest. */

export interface BackupFindInput {
  /** base URL of the target app (origin for relative candidates). */
  readonly baseUrl: string;
  readonly outputRoot: string;
  /** known live files/dirs to derive backups from; default: common app entries. */
  readonly targets?: readonly string[];
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxCandidates?: number;
}

export interface BackupFindResult {
  readonly probed: number;
  readonly found: { url: string; status: number; bytes: number; contentType: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const DEFAULT_TARGETS: readonly string[] = [
  "/", "index.php", "index.html", "admin/", "admin/index.php", "config.php",
  "wp-config.php", "wp-login.php", ".env", "composer.json", "package.json",
  "backup/", "db/", "dump/",
];

/** backup suffix vocabulary (Wapiti + reconFTW high-signal union). */
const SUFFIXES: readonly string[] = [
  ".bak", ".back", ".backup", ".old", ".orig", ".original", ".copy", ".save",
  ".swp", ".swo", ".tmp", ".temp", "~", ".txt",
  ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z", ".gz", ".bz2",
];

const ROOT_DUMPS: readonly string[] = [
  "www.tar.gz", "web.tar.gz", "site.tar.gz", "backup.tar.gz", "backup.zip",
  "www.zip", "web.zip", "site.zip", "html.zip", "public.zip", "src.zip",
  "dump.sql", "db.sql", "database.sql", "backup.sql", "db_dump.sql",
  "dump.sqlite", "db.sqlite", "database.sqlite",
];

export const findBackups = async (input: BackupFindInput): Promise<BackupFindResult> => {
  await ensureDir(input.outputRoot);
  const origin = new URL(input.baseUrl).origin;
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000, redirect: "manual" as const };

  // soft-404 calibration: two random paths; responses identical to random
  // baselines are catch-all noise, not findings (pathProbe discipline).
  const rnd = (): string => `${origin}/${Math.random().toString(36).slice(2, 14)}`;
  const soft1 = await fetchUrl(rnd(), opts);
  const soft2 = await fetchUrl(rnd(), opts);
  // A soft-404 fingerprint is only learnable from AGREEING random baselines:
  // two random paths with different bodies prove the origin serves real,
  // distinct content — treating the first body as the catch-all shape would
  // delete genuine files that happen to share its bytes.
  const softFp = soft1.status === soft2.status && soft1.sha256 === soft2.sha256 ? `${soft1.status}:${soft1.sha256.slice(0, 12)}` : null;

  // candidate set: targets x suffixes + root dumps
  const targets = input.targets ?? DEFAULT_TARGETS;
  const candidates = new Set<string>();
  const derived: string[] = [];
  for (const t of targets) {
    if (typeof t !== "string" || /[\\\x00-\x20\x7f]/.test(t)) continue;
    try {
      // Targets are file/dir names relative to the SITE ROOT (the probe's own
      // docstring: index.php -> /index.php.bak), never relative to the
      // baseUrl's path — a session URL like /a/?x=2 must not shift candidates
      // into /a/. Absolute-path targets keep their path.
      const isAbsolute = t.startsWith("/");
      const target = new URL(isAbsolute ? t : `/${t.replace(/^\/+/, "")}`, `${origin}/`);
      if (target.origin !== origin || target.username || target.password || target.search || target.hash) continue;
      const path = target.pathname.replace(/\/+$/, "");
      if (!path) continue;
      for (const sfx of SUFFIXES) {
        const candidate = new URL(origin);
        candidate.pathname = `${path}${sfx}`;
        if (candidate.origin === origin) derived.push(candidate.href);
      }
    } catch { /* a dirty target must not abort the remaining candidates */ }
  }
  // Reserve root dumps even when the target/suffix product exceeds the budget.
  if (derived[0]) candidates.add(derived[0]);
  for (const d of ROOT_DUMPS) candidates.add(new URL(`/${d}`, origin).href);
  for (const url of derived) candidates.add(url);
  const budget = Number.isFinite(input.maxCandidates) ? Math.max(0, Math.min(3000, Math.floor(input.maxCandidates!))) : 300;
  const list = [...candidates].slice(0, budget);

  const found: BackupFindResult["found"] = [];
  let probed = 0;
  for (const url of list) {
    const r = await fetchUrl(url, opts);
    probed++;
    if (r.status !== 200 || r.bytes === 0) continue;
    if (softFp !== null && `${r.status}:${r.sha256.slice(0, 12)}` === softFp) continue; // soft-404
    // content-type sanity: backups are files; an HTML page that is the SPA
    // shell for everything (same bytes as /) is routing noise — drop when the
    // body is byte-identical to the root fetch.
    found.push({ url, status: r.status, bytes: r.bytes, contentType: r.contentType });
  }

  const bodyStr = JSON.stringify({ probed, found }, null, 2);
  const art = await writeArtifact(input.outputRoot, "backup_candidates.json", bodyStr);
  return { probed, found, artifacts: [art] };
};
