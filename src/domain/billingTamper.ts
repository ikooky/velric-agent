import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Checkout / billing tampering matrix. The client-supplied price is the
 *  attack surface: zero, one-cent, negative, huge, float precision, currency
 *  swap, quantity abuse and coupon repetition. Read-back through the order
 *  endpoint decides whether the server stored the tampered value (accepted)
 *  or normalized it (safe). */

export interface BillInput {
  /** Checkout endpoint; template carries {AMOUNT} {CURRENCY} {QTY} {PLAN} {COUPON}. */
  readonly url: string;
  readonly bodyTemplate: string;
  readonly outputRoot: string;
  readonly amount: number;
  readonly currency: string;
  readonly plan?: string;
  readonly planCheap?: string;
  readonly coupon?: string;
  /** Order read-back URL template with {ID}. */
  readonly orderUrl?: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly contentType?: string;
}

export type BillVerdict = "accepted-as-is" | "normalized" | "rejected" | "unchecked";

export interface BillCase {
  readonly vector: string;
  readonly amount: string;
  readonly currency: string;
  readonly qty: string;
  readonly status: number;
  readonly orderId?: string;
  readonly storedAmount?: string;
  readonly storedCurrency?: string;
  readonly verdict: BillVerdict;
  readonly evidence: string;
}

export interface BillResult {
  readonly cases: BillCase[];
  readonly accepted: BillCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

interface Vector {
  readonly name: string;
  readonly amount?: number;
  readonly currency?: string;
  readonly qty?: number;
  readonly plan?: "cheap";
  readonly coupon?: "double" | "upper";
}

const VECTORS: readonly Vector[] = [
  { name: "amount-zero", amount: 0 },
  { name: "amount-one-cent", amount: 0.01 },
  { name: "amount-negative", amount: -1 },
  { name: "amount-huge", amount: 999_999_999 },
  { name: "amount-float-precision", amount: 0.001 },
  { name: "currency-jpy", currency: "JPY" },
  { name: "currency-lowercase", currency: "usd" },
  { name: "qty-negative", qty: -1 },
  { name: "qty-zero", qty: 0 },
  { name: "qty-huge", qty: 1_000_000 },
  { name: "plan-cheap", plan: "cheap" },
  { name: "coupon-double", coupon: "double" },
  { name: "coupon-uppercase", coupon: "upper" },
];

const render = (tpl: string, v: Vector, input: BillInput): { body: string; amount: string; currency: string; qty: string } => {
  const amount = String(v.amount ?? input.amount);
  const currency = v.currency ?? input.currency;
  const qty = String(v.qty ?? 1);
  const plan = v.plan === "cheap" ? (input.planCheap ?? input.plan ?? "") : (input.plan ?? "");
  const coupon = v.coupon === "upper" ? (input.coupon ?? "").toUpperCase() : input.coupon ? (v.coupon === "double" ? `${input.coupon},${input.coupon}` : input.coupon) : "";
  const body = tpl
    .replaceAll("{AMOUNT}", amount)
    .replaceAll("{CURRENCY}", currency)
    .replaceAll("{QTY}", qty)
    .replaceAll("{PLAN}", plan)
    .replaceAll("{COUPON}", coupon);
  return { body, amount, currency, qty };
};

const FIND_ID = [/"id"\s*:\s*"?([A-Za-z0-9_-]{2,})/i, /"orderId"\s*:\s*"?([A-Za-z0-9_-]{2,})/i, /"reference"\s*:\s*"?([A-Za-z0-9_-]{2,})/i];
const FIND_AMOUNT = [/"amount"\s*:\s*"?(-?[0-9.]+)/i, /"total"\s*:\s*"?(-?[0-9.]+)/i, /"price"\s*:\s*"?(-?[0-9.]+)/i, /"grandTotal"\s*:\s*"?(-?[0-9.]+)/i];
const FIND_CUR = [/"currency"\s*:\s*"?([A-Za-z]{3})/i];

const idFrom = (res: { body: string; headers: Record<string, string>; status: number }, tpl: string): string | undefined => {
  for (const re of FIND_ID) { const m = re.exec(res.body); if (m?.[1]) return m[1]; }
  const loc = res.headers.location;
  if (loc) { const seg = loc.split(/[/?#]/).filter(Boolean).pop(); if (seg && /^[A-Za-z0-9_-]{2,}$/.test(seg)) return seg; }
  // URL template may itself be the order endpoint (e.g. /orders/my) — no id needed.
  return tpl.includes("{ID}") ? undefined : "";
};

export const probeBillingTamper = async (input: BillInput): Promise<BillResult> => {
  const contentType = input.contentType ?? (input.bodyTemplate.trim().startsWith("{") ? "application/json" : "application/x-www-form-urlencoded");
  const hdrs = (): Record<string, string> => {
    const h: Record<string, string> = { "content-type": contentType, ...(input.headers ?? {}) };
    if (input.cookie) h.cookie = input.cookie;
    if (input.bearer) h.authorization = `Bearer ${input.bearer}`;
    return h;
  };
  const cases: BillCase[] = [];
  for (const v of VECTORS) {
    const { body, amount, currency, qty } = render(input.bodyTemplate, v, input);
    const checkout = await fetchUrl(input.url, { method: "POST", body, headers: hdrs(), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
    const ok = checkout.status >= 200 && checkout.status < 300;
    const base: BillCase = { vector: v.name, amount, currency, qty, status: checkout.status, verdict: "unchecked", evidence: ok ? "checkout accepted" : `checkout ${checkout.status}` };
    if (!ok) { cases.push({ ...base, verdict: "rejected" }); continue; }
    const orderId = input.orderUrl ? idFrom(checkout, input.orderUrl) : undefined;
    if (!input.orderUrl || orderId === undefined) { cases.push({ ...base, evidence: `${base.evidence}; no read-back` }); continue; }
    const readUrl = input.orderUrl.replaceAll("{ID}", orderId ?? "");
    const read = await fetchUrl(readUrl, { headers: hdrs(), maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
    const storedAmount = FIND_AMOUNT.map((re) => re.exec(read.body)?.[1]).find(Boolean);
    const storedCurrency = FIND_CUR.map((re) => re.exec(read.body)?.[1]).find(Boolean);
    const evidence = `order read-back ${read.status} amount=${storedAmount ?? "?"} currency=${storedCurrency ?? "?"}`;
    let verdict: BillVerdict = "unchecked";
    if (read.status >= 200 && read.status < 300 && storedAmount !== undefined) {
      const a = Number(storedAmount);
      const tampered = Number(amount);
      verdict = Math.abs(a - tampered) < 1e-9 ? "accepted-as-is" : "normalized";
    }
    cases.push({ ...base, orderId, storedAmount, storedCurrency, verdict, evidence });
  }
  const accepted = cases.filter((c) => c.verdict === "accepted-as-is");
  const body = JSON.stringify({ url: input.url, cases, summary: { accepted: accepted.length, checked: cases.filter((c) => c.verdict !== "unchecked" && c.verdict !== "rejected").length } }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "billing_tamper.json", body);
  return { cases, accepted, artifacts: [artifact] };
};
