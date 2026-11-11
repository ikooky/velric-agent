import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** Cloud object-storage exposure: anonymous bucket listing, object reads and
 *  (optionally) anonymous writes. S3/GCS/Azure conventions, region re-direct
 *  honoured, listing parsed for real key counts. A listable bucket is a full
 *  data dump; a writable one is defacement / stored-XSS supply. */

export type StorageProvider = "aws" | "gcs" | "azure";

export interface StorageInput {
  /** Bucket candidate(s): "name" (aws/gcs) or "account/container" (azure). */
  readonly buckets: readonly string[];
  readonly outputRoot: string;
  readonly provider?: StorageProvider;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  /** Anonymous write test: PUT canary, verify, DELETE (default false). */
  readonly write?: boolean;
  /** Endpoint override for tests/self-hosted gateways: "http://host:port" (bucket appended). */
  readonly endpoint?: string;
}

export interface StorageFinding {
  readonly bucket: string;
  readonly provider: StorageProvider;
  state: "public-list" | "public-object" | "write-enabled" | "authenticated" | "missing" | "error";
  readonly objectCount?: number;
  readonly keys?: readonly string[];
  evidence: string;
}

export interface StorageResult {
  readonly findings: StorageFinding[];
  readonly artifacts: { path: string; bytes: number }[];
}

const CANARY = "velric-canary.txt";

const urlFor = (p: StorageProvider, bucket: string, region?: string, endpoint?: string): string => {
  if (endpoint) {
    const suffix = p === "azure" ? "?restype=container&comp=list&maxresults=25" : "?list-type=2&max-keys=25";
    return `${endpoint}/${encodeURIComponent(bucket)}${suffix}`;
  }
  if (p === "gcs") return `https://storage.googleapis.com/${encodeURIComponent(bucket)}?max-keys=25`;
  if (p === "azure") {
    const [acct, container] = bucket.split("/");
    return `https://${acct}.blob.core.windows.net/${encodeURIComponent(container ?? "")}?restype=container&comp=list&maxresults=25`;
  }
  if (region && region !== "us-east-1") return `https://${bucket}.s3.${region}.amazonaws.com/?list-type=2&max-keys=25`;
  return `https://${bucket}.s3.amazonaws.com/?list-type=2&max-keys=25`;
};

const keysFrom = (p: StorageProvider, body: string): string[] => {
  const keys: string[] = [];
  if (p === "aws") for (const m of body.matchAll(/<Key>([^<]*)<\/Key>/g)) keys.push(m[1] ?? "");
  else if (p === "gcs") for (const m of body.matchAll(/<Key>([^<]*)<\/Key>/g)) keys.push(m[1] ?? "");
  else for (const m of body.matchAll(/<Name>([^<]*)<\/Name>/g)) keys.push(m[1] ?? "");
  return keys.filter(Boolean);
};

const detectProvider = (bucket: string): StorageProvider => (bucket.includes("/") ? "azure" : "aws");

export const probeCloudStorage = async (input: StorageInput): Promise<StorageResult> => {
  const findings: StorageFinding[] = [];
  for (const raw of input.buckets) {
    const bucket = raw.trim();
    if (!bucket) continue;
    const provider = input.provider ?? detectProvider(bucket);
    let region: string | undefined;
    let listUrl = urlFor(provider, bucket, region, input.endpoint);
    let r = await fetchUrl(listUrl, { maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
    if (provider === "aws" && r.status === 301 && r.headers["x-amz-bucket-region"]) {
      region = r.headers["x-amz-bucket-region"];
      listUrl = urlFor(provider, bucket, region, input.endpoint);
      r = await fetchUrl(listUrl, { maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 512 * 1024 });
    }
    const listing = /ListBucketResult|<EnumerationResults/.test(r.body);
    if (r.status >= 200 && r.status < 300 && listing) {
      const keys = keysFrom(provider, r.body);
      const count = Number(/<KeyCount>(\d+)<\/KeyCount>/.exec(r.body)?.[1] ?? keys.length);
      const f: StorageFinding = { bucket, provider, state: "public-list", objectCount: count, keys: keys.slice(0, 10), evidence: `${r.status} listing accepted, ${count} object(s) enumerated${region ? ` (region ${region})` : ""}` };
      if (input.write) {
        const putUrl = input.endpoint ? `${input.endpoint}/${encodeURIComponent(bucket)}/${CANARY}` : provider === "gcs"
          ? `https://storage.googleapis.com/${encodeURIComponent(bucket)}/${CANARY}`
          : provider === "azure"
            ? `https://${bucket.split("/")[0]}.blob.core.windows.net/${bucket.split("/")[1]}/${CANARY}`
            : `https://${bucket}.s3.${region && region !== "us-east-1" ? `${region}.` : ""}amazonaws.com/${CANARY}`;
        const put = await fetchUrl(putUrl, { method: "PUT", body: `velric ${new Date().toISOString()}`, maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 64 * 1024 });
        if (put.status >= 200 && put.status < 300) {
          const back = await fetchUrl(putUrl, { maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 64 * 1024 });
          f.state = back.status === 200 ? "write-enabled" : "public-list";
          f.evidence += back.status === 200 ? `; PUT+GET ${CANARY} succeeded` : `; PUT ${put.status}`;
          await fetchUrl(putUrl, { method: "DELETE", maxAttempts: 1, redirect: "manual", proxy: input.proxy, timeoutMs: input.timeoutMs ?? 10_000, maxBytes: 16 * 1024 });
        } else {
          f.evidence += `; PUT ${put.status}`;
        }
      }
      findings.push(f);
      continue;
    }
    if (r.status === 403 || r.status === 401) findings.push({ bucket, provider, state: "authenticated", evidence: `${r.status} — bucket exists, needs credentials${r.headers["x-amz-bucket-region"] ? ` (region ${r.headers["x-amz-bucket-region"]})` : ""}` });
    else if (r.status === 404 || /NoSuchBucket/.test(r.body)) findings.push({ bucket, provider, state: "missing", evidence: `${r.status} NoSuchBucket` });
    else findings.push({ bucket, provider, state: "error", evidence: `status ${r.status}${r.error ? ` ${r.error.slice(0, 80)}` : ""}` });
  }
  const body = JSON.stringify({ findings }, null, 2);
  const artifact = await writeArtifact(input.outputRoot, "cloud_storage.json", body);
  return { findings, artifacts: [artifact] };
};
