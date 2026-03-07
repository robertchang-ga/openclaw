import type { Api, Model } from "@mariozechner/pi-ai";
import { describe, expect, it } from "vitest";
import { isModernModelRef } from "./live-model-filter.js";
import { normalizeModelCompat } from "./model-compat.js";
import { resolveForwardCompatModel } from "./model-forward-compat.js";
import type { ModelRegistry } from "./pi-model-discovery.js";

const baseModel = (): Model<Api> =>
  ({
    id: "glm-4.7",
    name: "GLM-4.7",
    api: "openai-completions",
    provider: "zai",
    baseUrl: "https://api.z.ai/api/coding/paas/v4",
    reasoning: true,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 8192,
    maxTokens: 1024,
  }) as Model<Api>;

function createTemplateModel(provider: string, id: string): Model<Api> {
  return {
    id,
    name: id,
    provider,
    api: "anthropic-messages",
    input: ["text"],
    reasoning: true,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 200_000,
    maxTokens: 8_192,
  } as Model<Api>;
}

function createOpenAITemplateModel(id: string): Model<Api> {
  return {
    id,
    name: id,
    provider: "openai",
    api: "openai-responses",
    baseUrl: "https://api.openai.com/v1",
    input: ["text", "image"],
    reasoning: true,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 400_000,
    maxTokens: 32_768,
  } as Model<Api>;
}

function createOpenAICodexTemplateModel(id: string): Model<Api> {
  return {
    id,
    name: id,
    provider: "openai-codex",
    api: "openai-codex-responses",
    baseUrl: "https://chatgpt.com/backend-api",
    input: ["text", "image"],
    reasoning: true,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 272_000,
    maxTokens: 128_000,
  } as Model<Api>;
}

function createRegistry(models: Record<string, Model<Api>>): ModelRegistry {
  return {
    find(provider: string, modelId: string) {
      return models[`${provider}/${modelId}`] ?? null;
    },
  } as ModelRegistry;
}

describe("normalizeModelCompat — Anthropic baseUrl", () => {
  const anthropicBase = (): Model<Api> =>
    ({
      id: "claude-opus-4-6",
      name: "claude-opus-4-6",
      api: "anthropic-messages",
      provider: "anthropic",
      reasoning: true,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 200_000,
      maxTokens: 8_192,
    }) as Model<Api>;

  it("strips /v1 suffix from anthropic-messages baseUrl", () => {
    const model = { ...anthropicBase(), baseUrl: "https://api.anthropic.com/v1" };
    const normalized = normalizeModelCompat(model);
    expect(normalized.baseUrl).toBe("https://api.anthropic.com");
  });

  it("strips trailing /v1/ (with slash) from anthropic-messages baseUrl", () => {
    const model = { ...anthropicBase(), baseUrl: "https://api.anthropic.com/v1/" };
    const normalized = normalizeModelCompat(model);
    expect(normalized.baseUrl).toBe("https://api.anthropic.com");
  });

  it("leaves anthropic-messages baseUrl without /v1 unchanged", () => {
    const model = { ...anthropicBase(), baseUrl: "https://api.anthropic.com" };
    const normalized = normalizeModelCompat(model);
    expect(normalized.baseUrl).toBe("https://api.anthropic.com");
  });

  it("leaves baseUrl undefined unchanged for anthropic-messages", () => {
    const model = anthropicBase();
    const normalized = normalizeModelCompat(model);
    expect(normalized.baseUrl).toBeUndefined();
  });

  it("does not strip /v1 from non-anthropic-messages models", () => {
    const model = {
      ...baseModel(),
      provider: "openai",
      api: "openai-responses" as Api,
      baseUrl: "https://api.openai.com/v1",
    };
    const normalized = normalizeModelCompat(model);
    expect(normalized.baseUrl).toBe("https://api.openai.com/v1");
  });

  it("strips /v1 from custom Anthropic proxy baseUrl", () => {
    const model = {
      ...anthropicBase(),
      baseUrl: "https://my-proxy.example.com/anthropic/v1",
    };
    const normalized = normalizeModelCompat(model);
    expect(normalized.baseUrl).toBe("https://my-proxy.example.com/anthropic");
  });
});

describe("normalizeModelCompat", () => {
  it("forces supportsDeveloperRole off for z.ai models", () => {
    const model = baseModel();
    delete (model as { compat?: unknown }).compat;
    const normalized = normalizeModelCompat(model);
    expect(
      (normalized.compat as { supportsDeveloperRole?: boolean } | undefined)?.supportsDeveloperRole,
    ).toBe(false);
  });

  it("forces supportsDeveloperRole off for moonshot models", () => {
    const model = {
      ...baseModel(),
      provider: "moonshot",
      baseUrl: "https://api.moonshot.ai/v1",
    };
    delete (model as { compat?: unknown }).compat;
    const normalized = normalizeModelCompat(model);
    expect(
      (normalized.compat as { supportsDeveloperRole?: boolean } | undefined)?.supportsDeveloperRole,
    ).toBe(false);
  });

  it("forces supportsDeveloperRole off for custom moonshot-compatible endpoints", () => {
    const model = {
      ...baseModel(),
      provider: "custom-kimi",
      baseUrl: "https://api.moonshot.cn/v1",
    };
    delete (model as { compat?: unknown }).compat;
    const normalized = normalizeModelCompat(model);
    expect(
      (normalized.compat as { supportsDeveloperRole?: boolean } | undefined)?.supportsDeveloperRole,
    ).toBe(false);
  });

  it("forces supportsDeveloperRole off for DashScope provider ids", () => {
    const model = {
      ...baseModel(),
      provider: "dashscope",
      baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
    };
    delete (model as { compat?: unknown }).compat;
    const normalized = normalizeModelCompat(model);
    expect(
      (normalized.compat as { supportsDeveloperRole?: boolean } | undefined)?.supportsDeveloperRole,
    ).toBe(false);
  });

  it("forces supportsDeveloperRole off for DashScope-compatible endpoints", () => {
    const model = {
      ...baseModel(),
      provider: "custom-qwen",
      baseUrl: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
    };
    delete (model as { compat?: unknown }).compat;
    const normalized = normalizeModelCompat(model);
    expect(
      (normalized.compat as { supportsDeveloperRole?: boolean } | undefined)?.supportsDeveloperRole,
    ).toBe(false);
  });

  it("leaves non-zai models untouched", () => {
    const model = {
      ...baseModel(),
      provider: "openai",
      baseUrl: "https://api.openai.com/v1",
    };
    delete (model as { compat?: unknown }).compat;
    const normalized = normalizeModelCompat(model);
    expect(normalized.compat).toBeUndefined();
  });

  it("does not override explicit z.ai compat false", () => {
    const model = baseModel();
    model.compat = { supportsDeveloperRole: false };
    const normalized = normalizeModelCompat(model);
    expect(
      (normalized.compat as { supportsDeveloperRole?: boolean } | undefined)?.supportsDeveloperRole,
    ).toBe(false);
  });
});

describe("isModernModelRef", () => {
  it("includes OpenAI gpt-5.4 variants in modern selection", () => {
    expect(isModernModelRef({ provider: "openai", id: "gpt-5.4" })).toBe(true);
    expect(isModernModelRef({ provider: "openai", id: "gpt-5.4-pro" })).toBe(true);
    expect(isModernModelRef({ provider: "openai-codex", id: "gpt-5.4" })).toBe(true);
  });

  it("excludes opencode minimax variants from modern selection", () => {
    expect(isModernModelRef({ provider: "opencode", id: "minimax-m2.1" })).toBe(false);
    expect(isModernModelRef({ provider: "opencode", id: "minimax-m2.5" })).toBe(false);
  });

  it("keeps non-minimax opencode modern models", () => {
    expect(isModernModelRef({ provider: "opencode", id: "claude-opus-4-6" })).toBe(true);
    expect(isModernModelRef({ provider: "opencode", id: "gemini-3-pro" })).toBe(true);
  });
});

describe("resolveForwardCompatModel", () => {
  it("resolves openai gpt-5.4 via gpt-5.2 template", () => {
    const registry = createRegistry({
      "openai/gpt-5.2": createOpenAITemplateModel("gpt-5.2"),
    });
    const model = resolveForwardCompatModel("openai", "gpt-5.4", registry);
    expectResolvedForwardCompat(model, { provider: "openai", id: "gpt-5.4" });
    expect(model?.api).toBe("openai-responses");
    expect(model?.baseUrl).toBe("https://api.openai.com/v1");
    expect(model?.contextWindow).toBe(1_050_000);
    expect(model?.maxTokens).toBe(128_000);
  });

  it("resolves openai gpt-5.4 without templates using normalized fallback defaults", () => {
    const registry = createRegistry({});

    const model = resolveForwardCompatModel("openai", "gpt-5.4", registry);

    expectResolvedForwardCompat(model, { provider: "openai", id: "gpt-5.4" });
    expect(model?.api).toBe("openai-responses");
    expect(model?.baseUrl).toBe("https://api.openai.com/v1");
    expect(model?.input).toEqual(["text", "image"]);
    expect(model?.reasoning).toBe(true);
    expect(model?.contextWindow).toBe(1_050_000);
    expect(model?.maxTokens).toBe(128_000);
    expect(model?.cost).toEqual({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0 });
  });

  it("resolves openai gpt-5.4-pro via template fallback", () => {
    const registry = createRegistry({
      "openai/gpt-5.2": createOpenAITemplateModel("gpt-5.2"),
    });
    const model = resolveForwardCompatModel("openai", "gpt-5.4-pro", registry);
    expectResolvedForwardCompat(model, { provider: "openai", id: "gpt-5.4-pro" });
    expect(model?.api).toBe("openai-responses");
    expect(model?.baseUrl).toBe("https://api.openai.com/v1");
    expect(model?.contextWindow).toBe(1_050_000);
    expect(model?.maxTokens).toBe(128_000);
  });

  it("resolves openai-codex gpt-5.4 via codex template fallback", () => {
    const registry = createRegistry({
      "openai-codex/gpt-5.2-codex": createOpenAICodexTemplateModel("gpt-5.2-codex"),
    });
    const model = resolveForwardCompatModel("openai-codex", "gpt-5.4", registry);
    expectResolvedForwardCompat(model, { provider: "openai-codex", id: "gpt-5.4" });
    expect(model?.api).toBe("openai-codex-responses");
    expect(model?.baseUrl).toBe("https://chatgpt.com/backend-api");
    expect(model?.contextWindow).toBe(272_000);
    expect(model?.maxTokens).toBe(128_000);
  });

  it("resolves anthropic opus 4.6 via 4.5 template", () => {
    const registry = createRegistry({
      "anthropic/claude-opus-4-5": createTemplateModel("anthropic", "claude-opus-4-5"),
    });
    const model = resolveForwardCompatModel("anthropic", "claude-opus-4-6", registry);
    expect(model?.id).toBe("claude-opus-4-6");
    expect(model?.name).toBe("claude-opus-4-6");
    expect(model?.provider).toBe("anthropic");
  });

  it("resolves anthropic sonnet 4.6 dot variant with suffix", () => {
    const registry = createRegistry({
      "anthropic/claude-sonnet-4.5-20260219": createTemplateModel(
        "anthropic",
        "claude-sonnet-4.5-20260219",
      ),
    });
    const model = resolveForwardCompatModel("anthropic", "claude-sonnet-4.6-20260219", registry);
    expect(model?.id).toBe("claude-sonnet-4.6-20260219");
    expect(model?.name).toBe("claude-sonnet-4.6-20260219");
    expect(model?.provider).toBe("anthropic");
  });

  it("does not resolve anthropic 4.6 fallback for other providers", () => {
    const registry = createRegistry({
      "anthropic/claude-opus-4-5": createTemplateModel("anthropic", "claude-opus-4-5"),
    });
    const model = resolveForwardCompatModel("openai", "claude-opus-4-6", registry);
    expect(model).toBeUndefined();
  });
});
