import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { EvidenceStore } from "./graphs.js";

/** Finding↔evidence binding lifecycle (velric 漏洞流量证据.md, deterministic
 *  port): ordered bindings with roles (baseline/proof/verification/
 *  supporting), optimistic-version writes rejected on conflict (the 409
 *  semantics), reorder, unbind, and md-zip export with manifest +
 *  request/response sidecar layout. */

export type BindRole = "baseline" | "proof" | "verification" | "supporting";

export interface Binding {
  readonly id: string;
  readonly hash: string; // evidence blob sha256
  readonly role: BindRole;
  note?: string;
}

export interface FindingBindings {
  readonly findingId: string;
  /** Bumped on every mutation — writers must echo the version they read. */
  version: number;
  bindings: Binding[];
}

export interface BindingStore {
  findings: Record<string, FindingBindings>;
}

const FILE = "evidence_bindings.json";

const load = async (root: string): Promise<BindingStore> => {
  try { return JSON.parse(await readFile(join(root, FILE), "utf8")) as BindingStore; }
  catch { return { findings: {} }; }
};

const persist = async (root: string, st: BindingStore): Promise<void> => {
  await mkdir(root, { recursive: true });
  const tmp = join(root, `${FILE}.${process.pid}.${Math.random().toString(36).slice(2, 8)}.tmp`);
  await writeFile(tmp, JSON.stringify(st, null, 2));
  await import("node:fs/promises").then((fs) => fs.rename(tmp, join(root, FILE)));
};

export interface BindInput {
  readonly root: string;
  readonly findingId: string;
  /** Version the caller read (0 for first bind). Mismatch = conflict. */
  readonly expectedVersion: number;
  readonly refs: { hash: string; role: BindRole; note?: string }[];
}

export const bindEvidence = async (input: BindInput): Promise<{ version: number; bindings: Binding[] }> => {
  if (input.refs.length === 0) throw new Error("no refs");
  // Every hash must exist in the evidence store before binding (atomic: a
  // single missing hash rolls back the whole batch).
  const store = new EvidenceStore(input.root);
  await store.load();
  for (const r of input.refs) {
    const blob = await store.get(r.hash);
    if (blob === null) throw new Error(`unknown evidence hash: ${r.hash}`);
  }
  const st = await load(input.root);
  const f = st.findings[input.findingId] ?? { findingId: input.findingId, version: 0, bindings: [] };
  if (f.version !== input.expectedVersion) {
    throw Object.assign(new Error(`version conflict: expected ${input.expectedVersion}, current ${f.version} — re-read and retry`), { code: "version_conflict" });
  }
  for (const r of input.refs) {
    if (f.bindings.some((b) => b.hash === r.hash)) continue; // re-adding a hash is a no-op
    const maxId = f.bindings.reduce((m, b) => Math.max(m, Number(b.id.slice(1)) || 0), 0);
    f.bindings.push({ id: `b${maxId + 1}`, hash: r.hash, role: r.role, note: r.note });
  }
  f.version += 1;
  st.findings[input.findingId] = f;
  await persist(input.root, st);
  return { version: f.version, bindings: f.bindings };
};

export const updateBinding = async (input: {
  root: string; findingId: string; bindingId: string; expectedVersion: number; role?: BindRole; note?: string;
}): Promise<{ version: number }> => {
  const st = await load(input.root);
  const f = st.findings[input.findingId];
  if (!f) throw new Error("finding not bound");
  if (f.version !== input.expectedVersion) throw Object.assign(new Error(`version conflict: current ${f.version}`), { code: "version_conflict" });
  const b = f.bindings.find((x) => x.id === input.bindingId);
  if (!b) throw new Error("binding not found");
  if (input.role) (b as { role: BindRole }).role = input.role;
  if (input.note !== undefined) (b as { note?: string }).note = input.note;
  f.version += 1;
  await persist(input.root, st);
  return { version: f.version };
};

export const unbindEvidence = async (input: {
  root: string; findingId: string; bindingId: string; expectedVersion: number;
}): Promise<{ version: number }> => {
  const st = await load(input.root);
  const f = st.findings[input.findingId];
  if (!f) throw new Error("finding not bound");
  if (f.version !== input.expectedVersion) throw Object.assign(new Error(`version conflict: current ${f.version}`), { code: "version_conflict" });
  const before = f.bindings.length;
  f.bindings = f.bindings.filter((x) => x.id !== input.bindingId);
  if (f.bindings.length === before) throw new Error("binding not found");
  f.version += 1;
  await persist(input.root, st);
  return { version: f.version };
};

/** Full reorder — must list every binding id exactly once. */
export const reorderBindings = async (input: {
  root: string; findingId: string; expectedVersion: number; order: string[];
}): Promise<{ version: number }> => {
  const st = await load(input.root);
  const f = st.findings[input.findingId];
  if (!f) throw new Error("finding not bound");
  if (f.version !== input.expectedVersion) throw Object.assign(new Error(`version conflict: current ${f.version}`), { code: "version_conflict" });
  const have = new Set(f.bindings.map((b) => b.id));
  if (input.order.length !== have.size || input.order.some((id) => !have.has(id))) {
    throw new Error("order must be a complete permutation of binding ids");
  }
  f.bindings.sort((a, b) => input.order.indexOf(a.id) - input.order.indexOf(b.id));
  f.version += 1;
  await persist(input.root, st);
  return { version: f.version };
};

export const getBindings = async (root: string, findingId: string): Promise<FindingBindings | null> => {
  const st = await load(root);
  return st.findings[findingId] ?? null;
};

/** md-zip export: manifest.json + blob sidecars + a Markdown index. */
export const exportBindings = async (input: {
  root: string; findingId: string; zipPath: string;
}): Promise<{ entries: number; zipBytes: number }> => {
  const f = await getBindings(input.root, input.findingId);
  if (!f) throw new Error("finding not bound");
  const store = new EvidenceStore(input.root);
  await store.load();
  const { zipSync } = await import("fflate");
  const files: Record<string, Uint8Array> = {};
  const md: string[] = [`# evidence — ${input.findingId}`, "", `version: ${f.version}`, ""];
  for (const b of f.bindings) {
    const data = await store.get(b.hash);
    if (!data) throw new Error(`missing blob ${b.hash}`);
    files[`evidence/${b.id}.bin`] = new Uint8Array(data);
    files[`evidence/${b.id}.json`] = new Uint8Array(Buffer.from(JSON.stringify({ hash: b.hash, role: b.role, note: b.note, bytes: data.length }, null, 2)));
    md.push(`- ${b.id} — ${b.role} — sha256:${b.hash} (${data.length} B)${b.note ? ` — ${b.note}` : ""}`);
  }
  files["manifest.json"] = new Uint8Array(Buffer.from(JSON.stringify({ findingId: input.findingId, version: f.version, bindings: f.bindings }, null, 2)));
  files["index.md"] = new Uint8Array(Buffer.from(md.join("\n")));
  const zipped = zipSync(files);
  const { writeFile } = await import("node:fs/promises");
  await import("node:fs/promises").then((fs) => fs.mkdir(dirname(input.zipPath), { recursive: true }));
  await writeFile(input.zipPath, zipped);
  return { entries: f.bindings.length, zipBytes: zipped.length };
};
