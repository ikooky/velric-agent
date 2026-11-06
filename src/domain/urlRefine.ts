/** URL-pool refinement pipeline: two pure-local
 *  stages that make every downstream probe's input smaller and sharper.
 *
 *  dedupeUrls — zero-request URL list decluttering: incremental-path
 *    folding (/page/1/ == /page/2/), same-path-different-value folding
 *    (?id=1 == ?id=2), static-extension drop, human-content drop, plus
 *    fuzzy ID normalization (numeric/uuid/hash -> {id}).
 *
 *  classifyUrls — vulnerability-pattern tagging: parameter-name
 *    patterns mark URLs as xss/ssrf/redirect/lfi/sqli/idor candidates so
 *    downstream probes take targeted feeds instead of the whole pool. */

const STATIC_EXT_RE = /\.(?:jpg|jpeg|png|gif|webp|svg|ico|css|js|mjs|map|woff2?|ttf|eot|mp4|webm|mp3|pdf|zip|rar|7z|gz|tgz)(?:[?#]|$)/i;
/** human-written content paths (keep-content inverse) */
const HUMAN_CONTENT_RE = /\/(?:posts?|blog|news|articles?|categories?)\/[^/]{15,}\/?$/i;
/** fuzzy ID shapes — all fold to ONE {id} token: the point is
 *  collapsing "same endpoint, different entity" URLs. */
const FUZZY_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [/^\d+$/, "{id}"],
  [/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, "{id}"],
  [/^[0-9a-f]{16,}$/, "{id}"],
  [/^[A-Za-z0-9_\-]{20,}$/, "{id}"],
];

export interface DedupeUrlsInput {
  readonly urls: readonly string[];
  /** keep static extensions instead of dropping (default drop). */
  readonly keepStatic?: boolean;
  /** keep blog-like human content (default drop). */
  readonly keepContent?: boolean;
  /** fuzzy-normalize ID-ish path segments and param values before folding. */
  readonly fuzzy?: boolean;
  /** whitelist extensions (overrides the static drop for these). */
  readonly whitelist?: readonly string[];
  /** only URLs with query params / only without (default: both). */
  readonly params?: "has" | "none";
}

export interface DedupeUrlsResult {
  readonly input: number;
  readonly kept: number;
  readonly urls: string[];
}

const normalize = (raw: string, fuzzy: boolean): { key: string; url: URL } | null => {
  let u: URL;
  try { u = new URL(raw.trim()); } catch { return null; }
  if (!/^https?:$/.test(u.protocol) || u.username || u.password || /[\x00-\x1f\x7f\\]/.test(raw)) return null;
  // fold trailing slash
  if (u.pathname.length > 1 && u.pathname.endsWith("/")) u.pathname = u.pathname.slice(0, -1);
  if (fuzzy) {
    const segs = u.pathname.split("/").map((s) => {
      for (const [re, tok] of FUZZY_PATTERNS) if (re.test(s)) return tok;
      return s;
    });
    u.pathname = segs.join("/");
    for (const [k, v] of u.searchParams.entries()) {
      for (const [re, tok] of FUZZY_PATTERNS) {
        if (re.test(v)) { u.searchParams.set(k, tok); break; }
      }
    }
  }
  // param-name signature: sort param names, drop tracking noise entirely
  const tracking = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "ref", "referrer"]);
  for (const k of [...u.searchParams.keys()]) if (tracking.has(k.toLowerCase())) u.searchParams.delete(k);
  const names = [...u.searchParams.keys()].sort();
  const vals: string[] = [];
  for (const k of names) {
    // value folding: same name + same value SHAPE counts as same URL
    const v = u.searchParams.get(k) ?? "";
    vals.push(fuzzy && FUZZY_PATTERNS.some(([re]) => re.test(v)) ? "{id}" : "v");
  }
  const key = `${u.origin}${u.pathname}${names.length > 0 ? `?${names.map((n, i) => `${n}=${vals[i]}`).join("&")}` : ""}`;
  return { key, url: u };
};

export const dedupeUrls = (input: DedupeUrlsInput): DedupeUrlsResult => {
  const seen = new Map<string, string>(); // key -> representative original URL
  const wl = new Set((input.whitelist ?? []).map((e) => e.toLowerCase().replace(/^\./, "")));
  for (const raw of input.urls) {
    if (!raw || typeof raw !== "string") continue;
    const trimmed = raw.trim();
    if (!trimmed) continue;
    if (!input.keepStatic && STATIC_EXT_RE.test(trimmed)) {
      const ext = (trimmed.split("?")[0] ?? "").split(".").pop() ?? "";
      if (!wl.has(ext.toLowerCase())) continue;
    }
    const n = normalize(trimmed, input.fuzzy ?? true);
    if (!n) continue;
    if (!input.keepContent && HUMAN_CONTENT_RE.test(n.url.pathname)) continue;
    if (input.params === "has" && n.url.searchParams.size === 0) continue;
    if (input.params === "none" && n.url.searchParams.size > 0) continue;
    if (!seen.has(n.key)) seen.set(n.key, trimmed);
  }
  return { input: input.urls.length, kept: seen.size, urls: [...seen.values()] };
};

// ---------------------------------------------------------------------------
// vulnerability-pattern classification

/** Param-name/URL-shape patterns per attack class. */
export const GF_PATTERNS: ReadonlyArray<{ cls: string; paramRe: RegExp; pathRe?: RegExp }> = [
  {
    cls: "ssrf",
    paramRe: /^(?:url|uri|link|src|source|dest|destination|redirect(?:_uri|_url)?|next|rurl|return(?:_url|to)?|continue|callback(?:url)?|goto|target|u|image_url|feed|fetch|load|proxy|remote|host|domain|site|page_url|file_url)$/i,
  },
  {
    cls: "redirect",
    paramRe: /^(?:redirect|redirect_uri|redirect_url|next|return|returnUrl|return_to|continue|callback|callbackUrl|dest|destination|goto|rurl|url|u|target|link|out|away)$/i,
  },
  {
    cls: "lfi",
    paramRe: /^(?:file|filename|filepath|path|dir|directory|doc|document|page|template|include|require|cat|item|folder|load|view|content|resource|location|data)$/i,
  },
  {
    cls: "xss",
    paramRe: /^(?:q|query|search|keyword|keywords|s|name|title|message|comment|content|text|description|value|input|msg|body|html|render|format|output|callback)$/i,
  },
  {
    cls: "sqli",
    paramRe: /^(?:id|uid|pid|cid|sid|cat|category|product|item|page_id|post|news|art|article|report|user|user_id|userid|account|order|sort|order_by|orderby|column|table|select|filter|year|month|date|string|number|row|view|ref|key)$/i,
  },
  {
    cls: "idor",
    // numeric id-valued params of ANY name are IDOR candidates (idor-prescreen feeds)
    paramRe: /.*/,
    numericValueOnly: true,
  } as { cls: string; paramRe: RegExp; numericValueOnly?: boolean },
  {
    cls: "debug",
    paramRe: /^(?:debug|verbose|trace|test|dev)$/i,
    pathRe: /\/(?:debug|test|dev|internal|admin|staging|phpinfo|console|trace|actuator|druid|metrics)\b/i,
  },
];

export interface ClassifiedUrl {
  readonly url: string;
  readonly classes: string[];
  /** matching param names that triggered each class. */
  readonly evidence: { cls: string; param: string }[];
}

export interface ClassifyUrlsResult {
  readonly classified: number;
  readonly byClass: Record<string, string[]>;
  readonly urls: ClassifiedUrl[];
}

export const classifyUrls = (urls: readonly string[]): ClassifyUrlsResult => {
  const out: ClassifiedUrl[] = [];
  const byClass: Record<string, string[]> = {};
  for (const raw of urls) {
    if (typeof raw !== "string") continue;
    let u: URL;
    try { u = new URL(raw.trim()); } catch { continue; }
    if (!/^https?:$/.test(u.protocol) || u.username || u.password || /[\x00-\x1f\x7f\\]/.test(raw)) continue;
    const evidence: { cls: string; param: string }[] = [];
    const classes = new Set<string>();
    // path-shape classes first (no params needed)
    for (const p of GF_PATTERNS) {
      if (p.pathRe && p.pathRe.test(u.pathname)) {
        classes.add(p.cls);
        evidence.push({ cls: p.cls, param: "(path)" });
      }
    }
    for (const [k, v] of u.searchParams.entries()) {
      for (const p of GF_PATTERNS) {
        if (!p.paramRe) continue;
        const numericOnly = (p as { numericValueOnly?: boolean }).numericValueOnly === true;
        if (numericOnly) {
          if (/^\d{1,12}$/.test(v) && /^(?:id|uid|pid|cid|sid|user|user_id|userid|account|order|item|doc|ref|no|num|number|[a-z_]*_id)$/i.test(k)) {
            classes.add(p.cls);
            evidence.push({ cls: p.cls, param: k });
          }
          continue;
        }
        if (p.paramRe.test(k)) {
          classes.add(p.cls);
          evidence.push({ cls: p.cls, param: k });
        }
      }
    }
    if (classes.size > 0) {
      out.push({ url: raw.trim(), classes: [...classes], evidence });
      for (const c of classes) (byClass[c] ??= []).push(raw.trim());
    }
  }
  return { classified: out.length, byClass, urls: out };
};
