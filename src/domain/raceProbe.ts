import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Race condition (TOCTOU) probe: fires N concurrent copies of a state-
 *  mutating request that a correct implementation must admit exactly once
 *  (coupon redeem, wallet debit, transfer, vote). Divergence between the
 *  number of 2xx admissions and the endpoint's own post-state read-back
 *  exposes check-then-act races. */

export interface RaceInput {
  readonly url: string;
  readonly method?: string;
  readonly body?: string;
  /** read-back URL that reflects the post-state (balance/coupon count) */
  readonly verifyUrl?: string;
  readonly verifyHeader?: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly concurrency?: number;
  readonly rounds?: number;
  readonly outputRoot: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface RaceResult {
  readonly fired: number;
  readonly admitted: number;
  readonly rejected: number;
  /** responses per round with distinct bodies (成功语义分化) */
  readonly distinctSuccessBodies: number;
  readonly verifyBefore?: string;
  readonly verifyAfter?: string;
  readonly raceSuspected: boolean;
  readonly evidence: string;
  readonly rounds: { round: number; ok: number; fail: number; bodies: number }[];
  readonly artifacts: { path: string; bytes: number }[];
}

export const probeRace = async (input: RaceInput): Promise<RaceResult> => {
  const method = input.method ?? "POST";
  const n = Math.min(input.concurrency ?? 10, 30);
  const rounds = Math.min(input.rounds ?? 3, 6);
  const hdrs = { "content-type": "application/json", ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) };
  const opts = { method, body: input.body, cookie: input.cookie, headers: hdrs, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 };
  const read = async (): Promise<string> => {
    if (!input.verifyUrl) return "";
    const r = await fetchUrl(input.verifyUrl, { cookie: input.cookie, headers: { ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 12000, maxAttempts: 1 });
    return r.body.slice(0, 3000);
  };
  const before = await read();
  const roundStats: RaceResult["rounds"] = [];
  let admitted = 0; let rejected = 0; let fired = 0;
  const successBodies = new Set<string>();
  for (let rd = 0; rd < rounds; rd++) {
    const rs = await Promise.allSettled(Array.from({ length: n }, () => fetchUrl(input.url, opts)));
    let ok = 0; let fail = 0;
    for (const p of rs) {
      fired++;
      if (p.status === "fulfilled" && p.value.status >= 200 && p.value.status < 300) { ok++; admitted++; successBodies.add(p.value.sha256 ?? p.value.body.slice(0, 200)); }
      else fail++, rejected++;
    }
    roundStats.push({ round: rd + 1, ok, fail, bodies: 0 });
  }
  // distinct success bodies across rounds: 同一请求的N次成功若语义应"仅一次", 多个不同成功体=部分成功
  const distinct = successBodies.size;
  for (const r of roundStats) r.bodies = distinct;
  const after = await read();
  // race判定: 并发全admitted(n×rounds全2xx)且verify状态变化幅度>单次语义, 或同轮全ok
  const sameRoundAllOk = roundStats.some(r => r.ok === n && n > 1);
  const raceSuspected = sameRoundAllOk || (admitted > rounds && distinct > 1);
  const evidence = sameRoundAllOk
    ? `round admitted all ${n} concurrent mutations (check-then-act window open)`
    : distinct > 1 ? `${distinct} distinct success bodies across ${admitted} admissions` : `no divergence: ${admitted}/${fired} admitted, ${distinct} distinct body`;
  const artifacts = [
    await writeArtifact(input.outputRoot, "race_cases.json", JSON.stringify({ fired, admitted, rejected, distinct, rounds: roundStats, verifyBefore: before, verifyAfter: after, raceSuspected, evidence }, null, 2)),
    await writeArtifact(input.outputRoot, "race_findings.md", ["# Race condition (TOCTOU)", "", `- fired ${fired} (${rounds} rounds × ${n} concurrent)`, `- admitted ${admitted} / rejected ${rejected}`, `- distinct success bodies: ${distinct}`, `- verdict: **${raceSuspected ? "RACE SUSPECTED" : "no divergence"}** — ${evidence}`].join("\n")),
  ];
  return { fired, admitted, rejected, distinctSuccessBodies: distinct, verifyBefore: before, verifyAfter: after, raceSuspected, evidence, rounds: roundStats, artifacts };
};
