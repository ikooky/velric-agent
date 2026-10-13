import { mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

import { toolError } from "../domain/result.js";

/**
 * Artifact writing. Every producing tool writes only under a caller-supplied
 * output_root; nothing is written anywhere else, and nothing is remembered
 * between calls. Refusing non-absolute roots keeps the write boundary explicit.
 */

export const assertAbsoluteRoot = (outputRoot: string): string => {
  if (!isAbsolute(outputRoot)) {
    throw toolError(
      "invalid_output_root",
      "output_root must be an absolute path",
      {
        details: { output_root: outputRoot },
        remediation: "pass an absolute directory, e.g. /tmp/recon",
      },
    );
  }
  return outputRoot;
};

/** Join a relative artifact name under output_root, refusing path escapes. */
export const artifactPath = (outputRoot: string, name: string): string => {
  const root = resolve(assertAbsoluteRoot(outputRoot));
  const target = resolve(root, name);
  const rel = relative(root, target);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
    throw toolError("path_escape", "artifact path escapes output_root", {
      details: { output_root: root, name },
    });
  }
  return target;
};

export const writeArtifact = async (
  outputRoot: string,
  name: string,
  content: string | Uint8Array,
): Promise<{ path: string; bytes: number }> => {
  const target = artifactPath(outputRoot, name);
  await mkdir(resolve(target, ".."), { recursive: true });
  await writeFile(target, content);
  const bytes =
    typeof content === "string" ? Buffer.byteLength(content) : content.length;
  return { path: target, bytes };
};

export const ensureDir = async (outputRoot: string): Promise<string> => {
  const root = assertAbsoluteRoot(outputRoot);
  await mkdir(root, { recursive: true });
  return root;
};