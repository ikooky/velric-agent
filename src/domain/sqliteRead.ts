import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { createRequire } from "node:module";

const require_ = createRequire(import.meta.url);

/** SQLite leak reader: parses a .db file with the WASM sqlite build (no
 *  native compile), lists tables + row counts, flags sensitive tables,
 *  and samples rows from password/token/user tables. */

export interface SqliteReadInput {
  readonly file: string;
  readonly outputRoot: string;
  readonly sampleLimit?: number;
}

export interface SqliteReadResult {
  readonly file: string;
  readonly opened: boolean;
  readonly tables: { name: string; rows: number; columns: string[] }[];
  readonly sensitive: { table: string; why: string; sample: string[] }[];
  readonly artifacts: { path: string; bytes: number }[];
}

const SENSITIVE_TABLE_RE = /password|passwd|pwd|user|account|token|secret|session|cookie|credential|key|admin|order|payment|invoice/i;
const SENSITIVE_COLUMN_RE = /password|passwd|pwd|token|secret|salt|hash|email|phone|idcard|credit/i;

interface SqlDb {
  exec: (sql: string) => { columns: string[]; values: unknown[][] }[];
  close: () => void;
}

export const readSqlite = async (input: SqliteReadInput): Promise<SqliteReadResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const result = { file: input.file, opened: false, tables: [] as { name: string; rows: number; columns: string[] }[], sensitive: [] as { table: string; why: string; sample: string[] }[], artifacts: [] as { path: string; bytes: number }[] };

  let db: SqlDb;
  try {
    const initSqlJs = require_("sql.js") as (cfg?: { locateFile?: (f: string) => string }) => Promise<{ Database: new (data?: Buffer) => SqlDb }>;
    // require_.resolve("sql.js") lands inside dist/ — no extra segment.
    const sqljsDist = dirname(require_.resolve("sql.js"));
    const SQL = await initSqlJs({ locateFile: (f: string) => join(sqljsDist, f) });
    const buf = await readFile(input.file);
    db = new SQL.Database(buf);
  } catch {
    const body = JSON.stringify(result, null, 2);
    const path = join(input.outputRoot, "sqlite_read.json");
    await writeFile(path, body);
    return { ...result, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
  }

  result.opened = true;
  const list = db.exec("SELECT name FROM sqlite_master WHERE type='table'");
  // Only safe identifiers may flow into per-table queries; hostile .db
  // files can plant crafted names in sqlite_master (SQL breakout).
  const names: string[] = (list[0]?.values.map((v) => String(v[0])) ?? [])
    .filter((n) => /^[A-Za-z0-9_ ]+$/.test(n));

  for (const name of names) {
    if (name.startsWith("sqlite_")) continue;
    let rows = 0;
    let columns: string[] = [];
    try {
      const cnt = db.exec(`SELECT COUNT(*) FROM "${name}"`);
      rows = Number(cnt[0]?.values[0]?.[0] ?? 0);
      const info = db.exec(`PRAGMA table_info("${name}")`);
      columns = info[0]?.values.map((v) => String(v[1])) ?? [];
    } catch { continue; }
    result.tables.push({ name, rows, columns });

    const tableHit = SENSITIVE_TABLE_RE.test(name);
    const columnHit = columns.some((c) => SENSITIVE_COLUMN_RE.test(c));
    if (tableHit || columnHit) {
      const why = tableHit ? "sensitive table name" : `sensitive column: ${columns.filter((c) => SENSITIVE_COLUMN_RE.test(c)).join(", ")}`;
      let sample: string[] = [];
      try {
        const lim = Math.min(Math.max(1, Number.isFinite(Number(input.sampleLimit)) ? Number(input.sampleLimit) : 5), 1000);
        const s = db.exec(`SELECT * FROM "${name}" LIMIT ${lim}`);
        sample = (s[0]?.values ?? []).map((row) => JSON.stringify(row).slice(0, 200));
      } catch { /* unreadable */ }
      result.sensitive.push({ table: name, why, sample });
    }
  }
  db.close();

  const body = JSON.stringify(result, null, 2);
  const path = join(input.outputRoot, "sqlite_read.json");
  await writeFile(path, body);
  return { ...result, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
