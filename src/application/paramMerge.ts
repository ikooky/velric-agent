import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { writeArtifact } from "../adapters/artifacts.js";
import { mergeParams, type ParamSample } from "../domain/params.js";

export interface ParamMergeInput {
  readonly samplesFile: string;
  readonly outputRoot: string;
}

export interface ParamMergeResult {
  readonly samples: number;
  readonly endpoints: number;
  readonly artifacts: { path: string; bytes: number }[];
}

/**
 * Merge recorded parameter samples (param_samples.json — array of
 * {method,url,action,body,query}) into per-endpoint field sets with
 * confidence, per api-recon J7. No scripts decide required/optional from a
 * single sample: the confidence column carries that honesty.
 */
export const mergeParamSamples = async (
  input: ParamMergeInput,
): Promise<ParamMergeResult> => {
  let raw: string;
  try {
    raw = await readFile(input.samplesFile, "utf8");
  } catch (cause) {
    throw {
      code: "samples_unreadable",
      message: `cannot read ${input.samplesFile}`,
      details: { error: cause instanceof Error ? cause.message : String(cause) },
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw {
      code: "samples_invalid_json",
      message: `samples file is not valid JSON: ${input.samplesFile}`,
    };
  }
  if (!Array.isArray(parsed)) {
    throw {
      code: "samples_invalid_shape",
      message: "samples file must be a JSON array of {method,url,body,query}",
    };
  }
  const samples = parsed as ParamSample[];
  const merged = mergeParams(samples);

  const artifacts: { path: string; bytes: number }[] = [];
  artifacts.push(
    await writeArtifact(
      input.outputRoot,
      "params_merged.json",
      JSON.stringify(merged, null, 2),
    ),
  );
  const lines = merged.map((e) => {
    const fields = e.fields.map((f) => `${f.in}:${f.name}(${f.confidence})`);
    return `${e.method} ${e.path} [${fields.join(", ")}]`;
  });
  artifacts.push(
    await writeArtifact(input.outputRoot, "params_merged.txt", lines.join("\n")),
  );

  return {
    samples: samples.length,
    endpoints: merged.length,
    artifacts,
  };
};

