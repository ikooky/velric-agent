import { parse } from "parse5";

export interface MpaForm {
  readonly method: string;
  readonly action: string;
  readonly params: string[];
}

export interface MpaPage {
  readonly links: string[];
  readonly scripts: string[];
  readonly inline: string[];
  readonly forms: MpaForm[];
}

/** Parse one HTML document into links/scripts/inline-urls/forms. */
export const parseMpaPage = (html: string): MpaPage => {
  const links: string[] = [];
  const scripts: string[] = [];
  const inline: string[] = [];
  const forms: MpaForm[] = [];
  let currentForm: { action: string; method: string; params: Set<string> } | null = null;

  const doc = parse(html);
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (node === null || typeof node !== "object") return;
    const el = node as {
      tagName?: string;
      attrs?: { name: string; value: string }[];
      childNodes?: unknown[];
      value?: string;
    };
    const attrs: Record<string, string> = {};
    for (const a of el.attrs ?? []) attrs[a.name] = a.value;
    switch (el.tagName) {
      case "a":
        if (attrs.href) links.push(attrs.href);
        break;
      case "script":
        if (attrs.src) scripts.push(attrs.src);
        break;
      case "form":
        currentForm = {
          action: attrs.action ?? "",
          method: (attrs.method ?? "GET").toUpperCase(),
          params: new Set(),
        };
        break;
      case "input":
      case "select":
      case "textarea":
      case "button":
        if (currentForm && attrs.name) currentForm.params.add(attrs.name);
        break;
    }
    if (el.childNodes) walk(el.childNodes);
    if (el.tagName === "form" && currentForm) {
      forms.push({
        action: currentForm.action,
        method: currentForm.method,
        params: [...currentForm.params].sort(),
      });
      currentForm = null;
    }
  };
  walk(doc);

  // inline script text
  const scriptTexts: string[] = [];
  const collectText = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(collectText);
      return;
    }
    if (node === null || typeof node !== "object") return;
    const el = node as { tagName?: string; value?: string; childNodes?: unknown[] };
    if (el.tagName === "script" && typeof el.value === "string") {
      scriptTexts.push(el.value);
    }
    if (el.childNodes) collectText(el.childNodes);
  };
  collectText(doc);
  for (const t of scriptTexts) {
    for (const m of t.matchAll(/["'`](\/[A-Za-z0-9_\-./{}$:?=&]{2,120})["'`]/g)) {
      inline.push(m[1]!);
    }
  }

  return {
    links: [...new Set(links)],
    scripts,
    inline: [...new Set(inline)],
    forms,
  };
};