import { fetchUrl } from "../adapters/http.js";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** Minimal template-based matcher engine (nuclei-style semantics, pure JS):
 *  each template declares target paths + match conditions (status / word /
 *  regex on body or headers). Ships a curated built-in template set for
 *  exposed panels and default pages. No PoC execution — read-only GETs. */

export interface NucleiTemplate {
  readonly id: string;
  readonly severity: "critical" | "high" | "medium" | "low" | "info";
  readonly name: string;
  readonly paths: readonly string[];
  readonly match: {
    readonly status?: readonly number[];
    readonly word?: readonly string[];
    readonly regex?: readonly string[];
    readonly negative?: boolean;
  };
}

export interface NucleiLiteInput {
  readonly baseUrl: string;
  readonly outputRoot: string;
  readonly templates?: NucleiTemplate[];
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly concurrency?: number;
}

export interface NucleiLiteResult {
  readonly baseUrl: string;
  readonly scanned: number;
  readonly matched: { id: string; severity: string; name: string; url: string; evidence: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

export const BUILTIN_TEMPLATES: readonly NucleiTemplate[] = [
  {
    id: "exposed-kibana",
    severity: "high",
    name: "Kibana panel exposed",
    paths: ["/app/kibana"],
    match: { status: [200], word: ["kbn-injected-metadata", "kibanaName"] },
  },
  {
    id: "exposed-grafana",
    severity: "medium",
    name: "Grafana login page",
    paths: ["/login"],
    match: { status: [200], word: ["grafana", "ng-scope", "buildInfo"] },
  },
  {
    id: "exposed-jenkins",
    severity: "high",
    name: "Jenkins panel",
    paths: ["/login"],
    match: { status: [200], word: ["jenkins", "Jenkins-Crumb"] },
  },
  {
    id: "exposed-spring-boot-env",
    severity: "critical",
    name: "Spring Boot actuator env",
    paths: ["/actuator/env"],
    match: { status: [200], regex: ['"(?:java|sun)\\.(?:version|boot)'] },
  },
  {
    id: "exposed-swagger-ui",
    severity: "medium",
    name: "Swagger UI",
    paths: ["/swagger-ui.html", "/swagger-ui/index.html"],
    match: { status: [200], word: ["swagger", "redoc"] },
  },
  {
    id: "exposed-phpmyadmin",
    severity: "medium",
    name: "phpMyAdmin",
    paths: ["/phpmyadmin/"],
    match: { status: [200], word: ["phpMyAdmin", "pma_password"] },
  },
  {
    id: "exposed-nacos",
    severity: "high",
    name: "Nacos console",
    paths: ["/nacos/"],
    match: { status: [200], word: ["nacos", "console-ui"] },
  },
  {
    id: "default-tomcat",
    severity: "low",
    name: "Tomcat default page",
    paths: ["/"],
    match: { status: [200], word: ["Apache Tomcat"] },
  },
  {
    id: "default-nginx",
    severity: "info",
    name: "nginx default page",
    paths: ["/"],
    match: { status: [200], word: ["Welcome to nginx"] },
  },
  {
    id: "git-config",
    severity: "critical",
    name: "Git config leak",
    paths: ["/.git/config"],
    match: { status: [200], regex: ["\\[core\\]"] },
  },
  {
    id: "env-file",
    severity: "critical",
    name: ".env file leak",
    paths: ["/.env"],
    match: { status: [200], regex: ["(?:PASSWORD|SECRET|TOKEN|API_KEY)\\s*="] },
  },
  {
    id: "exposed-ds-dir",
    severity: "low",
    name: "Directory listing",
    paths: ["/static/", "/uploads/"],
    match: { status: [200], word: ["Index of /"] },
  },
];

export const runNucleiLite = async (input: NucleiLiteInput): Promise<NucleiLiteResult> => {
  const base = input.baseUrl.replace(/\/$/, "");
  await mkdir(input.outputRoot, { recursive: true });
  const templates = input.templates ?? BUILTIN_TEMPLATES;
  const opts = { proxy: input.proxy, timeoutMs: input.timeoutMs ?? 8000 };
  const matched: NucleiLiteResult["matched"] = [];
  let scanned = 0;

  const jobs: { tpl: NucleiTemplate; path: string }[] = [];
  for (const tpl of templates) for (const p of tpl.paths) jobs.push({ tpl, path: p });

  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < jobs.length) {
      const job = jobs[cursor++]!;
      const r = await fetchUrl(base + job.path, opts);
      scanned++;
      const statusOk = job.tpl.match.status ? job.tpl.match.status.includes(r.status) : r.status === 200;
      if (!statusOk) continue;
      const wordsOk = job.tpl.match.word ? job.tpl.match.word.some((w) => r.body.includes(w)) !== (job.tpl.match.negative ?? false) : true;
      const regexOk = job.tpl.match.regex ? job.tpl.match.regex.some((re) => new RegExp(re, "i").test(r.body)) !== (job.tpl.match.negative ?? false) : true;

      if (statusOk && wordsOk && regexOk) {
        const evidence = job.tpl.match.word?.find((w) => r.body.includes(w)) ?? job.tpl.match.regex?.find((re) => new RegExp(re, "i").test(r.body)) ?? `status ${r.status}`;
        matched.push({ id: job.tpl.id, severity: job.tpl.severity, name: job.tpl.name, url: r.url, evidence });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(input.concurrency ?? 6, jobs.length) }, worker));

  const result: NucleiLiteResult = { baseUrl: base, scanned, matched, artifacts: [] };
  const body = JSON.stringify(result, null, 2);
  const path = join(input.outputRoot, "nuclei_lite.json");
  await writeFile(path, body);
  result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
  return result;
};
