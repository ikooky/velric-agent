import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** GraphQL query-depth & alias-bombing surface: measures whether the server
 *  enforces depth/complexity limits by firing bounded escalation ladders
 *  (depth 2..N, alias fan-out 2^k) and classifying rejections. */

export interface GqlBatchInput {
  readonly url: string;
  /** a leaf query template with {NEST} placeholder for nesting and {I} for alias index */
  readonly queryTemplate?: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly maxDepth?: number;
}
export interface GqlResult {
  readonly probed: number;
  readonly depthLadder: { depth: number; status: number; ms: number; rejected: boolean; len: number }[];
  readonly aliasLadder: { aliases: number; status: number; ms: number; rejected: boolean; len: number }[];
  readonly unboundedDepth: boolean;
  readonly unboundedAliases: boolean;
  readonly artifacts: { path: string; bytes: number }[];
}

export const probeGraphqlBatch = async (input: GqlBatchInput): Promise<GqlResult> => {
  const maxDepth = Math.min(input.maxDepth ?? 9, 12);
  const tpl = input.queryTemplate ?? 'query { country(code: "CN") { name {NEST} } }';
  const nestUnit = tpl.includes("{NEST}") ? 'continent { countries { code name } '.replace(/ \{ code name \}/, "") : "";
  const hdrs = { "content-type": "application/json", ...(input.headers ?? {}) };
  const send = async (query: string): Promise<{ status: number; ms: number; len: number; body: string }> => {
    const t0 = Date.now();
    const r = await fetchUrl(input.url, { method: "POST", body: JSON.stringify({ query }), cookie: input.cookie, headers: hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 20000, maxAttempts: 1 });
    return { status: r.status, ms: Date.now() - t0, len: r.bytes, body: r.body };
  };
  // depth ladder: 模板里{NEST}逐层替换(自身引用)
  const depthLadder: GqlResult["depthLadder"] = [];
  let deepestOk = 0;
  for (let d = 1; d <= maxDepth; d++) {
    // 构造: country { code {NEST} } -> {NEST}=嵌套d层的自我复制
    let q = tpl.replace("{NEST}", "");
    if (d > 1) {
      const unit = tpl.match(/\w+\s*\([^)]*\)\s*\{/);
      const field = unit ? unit[0] : "country(code: \"CN\") {";
      const inner = tpl.replace(/\{NEST\}/, "").replace(/^[^{]*\{/, "").replace(/\}[^}]*$/, "");
      // 简化: 逐层包
      let nested = tpl.replace("{NEST}", "");
      for (let i = 1; i < d; i++) nested = tpl.replace("{NEST}", "").replace(/^(\s*\w+\s*\(?[^{]*\{)/, `$1 ${nested.trim()}`);
      q = nested;
    }
    try {
      const r = await send(q);
      const rejected = r.status >= 400 || /too deep|depth|complexity|limit|exceed/i.test(r.body.slice(0, 300));
      depthLadder.push({ depth: d, status: r.status, ms: r.ms, rejected, len: r.len });
      if (!rejected && r.status < 300) deepestOk = d;
    } catch { depthLadder.push({ depth: d, status: 0, ms: -1, rejected: true, len: 0 }); }
  }
  // alias ladder: 同字段别名扇出
  const aliasLadder: GqlResult["aliasLadder"] = [];
  let aliasesOk = 0;
  for (const k of [2, 8, 32, 128, 512]) {
    const base = tpl.replace("{NEST}", "");
    const m = /^query\s*(?:\w+)?\s*\{(.+)\}\s*$/.exec(base.trim());
    const inner = m?.[1]?.trim() ?? 'country(code:"CN"){name}';
    const aliased = Array.from({ length: k }, (_, i) => `a${i}: ${inner}`).join("\n");
    const q = `query { ${aliased} }`;
    try {
      const r = await send(q);
      const rejected = r.status >= 400 || /complexity|too many|limit|abuse/i.test(r.body.slice(0, 300));
      aliasLadder.push({ aliases: k, status: r.status, ms: r.ms, rejected, len: r.len });
      if (!rejected && r.status < 300) aliasesOk = k;
    } catch { aliasLadder.push({ aliases: k, status: 0, ms: -1, rejected: true, len: 0 }); }
  }
  const unboundedDepth = deepestOk >= maxDepth;
  const unboundedAliases = aliasesOk >= 512;
  const artifacts = [
    await writeArtifact(input.outputRoot, "graphql_batch.json", JSON.stringify({ depthLadder, aliasLadder, unboundedDepth, unboundedAliases }, null, 2)),
    await writeArtifact(input.outputRoot, "graphql_batch.md", ["# GraphQL depth/alias limits", "", `deepest accepted depth: ${deepestOk}${unboundedDepth ? " (hit probe ceiling — effectively unbounded)" : ""}`, `largest accepted alias fan-out: ${aliasesOk}${unboundedAliases ? " (512 reached — effectively unbounded)" : ""}`].join("\n")),
  ];
  return { probed: depthLadder.length + aliasLadder.length, depthLadder, aliasLadder, unboundedDepth, unboundedAliases, artifacts };
};
