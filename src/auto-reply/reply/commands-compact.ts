import { logVerbose } from "../../globals.js";
import type { CommandHandler } from "./commands-types.js";

/**
 * /compact command handler — DEPRECATED.
 * Compaction has been replaced by the memory consolidation sleep cycle.
 */
export const handleCompactCommand: CommandHandler = async (params) => {
  const compactRequested =
    params.command.commandBodyNormalized === "/compact" ||
    params.command.commandBodyNormalized.startsWith("/compact ");
  if (!compactRequested) {
    return null;
  }
  if (!params.command.isAuthorizedSender) {
    logVerbose(
      `Ignoring /compact from unauthorized sender: ${params.command.senderId || "<unknown>"}`,
    );
    return { shouldContinue: false };
  }
  return {
    shouldContinue: false,
    reply: {
      text: "⚙️ Compaction is disabled. Memory consolidation runs automatically at midnight, on context overflow, and on session reset.",
    },
  };
};
