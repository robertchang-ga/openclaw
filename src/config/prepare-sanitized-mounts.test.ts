import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { withTempHome } from "./home-env.test-harness.js";
import { prepareSanitizedMounts } from "./prepare-sanitized-mounts.js";

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

describe("prepareSanitizedMounts", () => {
  afterEach(async () => {
    delete process.env.OPENCLAW_CONFIG_PATH;
  });

  it("preserves oauth accountId in sanitized auth profiles", async () => {
    await withTempHome("prepare-sanitized-mounts", async (home) => {
      const stateDir = path.join(home, ".openclaw");
      const authDir = path.join(stateDir, "agents", "main", "agent");
      await fs.mkdir(authDir, { recursive: true });

      const configPath = path.join(stateDir, "openclaw.json");
      await fs.writeFile(configPath, "{}\n", "utf8");
      process.env.OPENCLAW_CONFIG_PATH = configPath;

      await fs.writeFile(
        path.join(authDir, "auth-profiles.json"),
        `${JSON.stringify(
          {
            version: 1,
            profiles: {
              "openai-codex:default": {
                type: "oauth",
                provider: "openai-codex",
                email: "dev@example.com",
                accountId: "acct-123",
                access: "real-access-token",
                refresh: "real-refresh-token",
                expires: Date.now() + 60_000,
              },
            },
          },
          null,
          2,
        )}\n`,
        "utf8",
      );

      const mounts = await prepareSanitizedMounts();
      const sanitizedAuthPath = path.join(
        mounts.sanitizedDir,
        "agents",
        "main",
        "agent",
        "auth-profiles.json",
      );

      expect(await pathExists(sanitizedAuthPath)).toBe(true);

      const sanitized = JSON.parse(await fs.readFile(sanitizedAuthPath, "utf8")) as {
        profiles: Record<string, Record<string, unknown>>;
      };
      expect(sanitized.profiles["openai-codex:default"]).toMatchObject({
        type: "oauth",
        provider: "openai-codex",
        email: "dev@example.com",
        accountId: "acct-123",
        access: "{{OAUTH:openai-codex:default}}",
        refresh: "{{OAUTH_REFRESH:openai-codex:default}}",
        expires: 0,
      });
    });
  });
});
