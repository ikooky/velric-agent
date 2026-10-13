/** OpenAI-compatible chat client (z-api.pp.ua / any base_url + key). */
import { request as undiciRequest } from "undici";

export interface LlmConfig {
  readonly maxTokens?: number;
  readonly baseUrl: string; // e.g. https://z-api.pp.ua/v1
  readonly apiKey: string;
  readonly model: string;
}

export interface ChatMessage {
  readonly role: "system" | "user" | "assistant";
  readonly content: string;
}

const chatOnce = async (
  cfg: LlmConfig,
  messages: ChatMessage[],
  timeoutMs = 120000,
): Promise<string> => {
  const res = await undiciRequest(`${cfg.baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${cfg.apiKey}`,
    },
    body: JSON.stringify({
      model: cfg.model,
      messages,
      temperature: 0.2,
      max_tokens: cfg.maxTokens ?? 8192,
    }),
    bodyTimeout: timeoutMs,
    headersTimeout: timeoutMs,
  });
  if (res.statusCode !== 200) {
    const t = await res.body.text().catch(() => "");
    throw new Error(`llm http ${res.statusCode}: ${t.slice(0, 200)}`);
  }
  const j = JSON.parse((await res.body.text())) as {
    choices?: { message?: { content?: string | null; reasoning?: string | null; reasoning_content?: string | null }; finish_reason?: string | null }[];
  };
  const msg = j.choices?.[0]?.message;
  // Reasoning models (glm etc.) can exhaust the token budget on reasoning and
  // return content=null with finish_reason=length; retry at a higher budget.
  const content = msg?.content ?? null;
  if (!content) {
    const finish = j.choices?.[0]?.finish_reason;
    if (finish === "length") throw new Error("llm empty response (finish=length; raise max_tokens)");
    throw new Error("llm empty response");
  }
  return content;
};

/** Chat with retries (user convention: 3 attempts, 1s apart). */
export const chat = async (
  cfg: LlmConfig,
  messages: ChatMessage[],
  timeoutMs = 120000,
): Promise<string> => {
  let lastErr: Error | null = null;
  let budget = cfg.maxTokens ?? 8192;
  for (let i = 0; i < 3; i++) {
    try {
      return await chatOnce({ ...cfg, maxTokens: budget }, messages, timeoutMs);
    } catch (e) {
      lastErr = e as Error;
      if (String((e as Error).message).includes("finish=length")) budget = Math.min(budget * 2, 32768);
      if (i < 2) await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw lastErr ?? new Error("llm failed");
};

/** Extract the first JSON object from model output (fenced or bare). */
export const extractJson = <T>(text: string): T => {
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const raw = fence ? fence[1]! : text;
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error(`no json in output: ${text.slice(0, 120)}`);
  return JSON.parse(raw.slice(start, end + 1)) as T;
};
