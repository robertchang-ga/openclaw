import { render } from "lit";
import { describe, expect, it, vi } from "vitest";

import type { GatewaySessionRow, SessionsListResult } from "../types";
import { renderSessions, type SessionsProps } from "./sessions";

function createRow(overrides: Partial<GatewaySessionRow> = {}): GatewaySessionRow {
  return {
    key: "session-1",
    kind: "direct",
    updatedAt: 0,
    ...overrides,
  };
}

function createResult(rows: GatewaySessionRow[]): SessionsListResult {
  return {
    ts: 0,
    path: "/sessions",
    count: rows.length,
    defaults: {
      model: null,
      contextTokens: null,
    },
    sessions: rows,
  };
}

function createProps(overrides: Partial<SessionsProps> = {}): SessionsProps {
  return {
    loading: false,
    result: createResult([]),
    error: null,
    activeMinutes: "",
    limit: "",
    includeGlobal: true,
    includeUnknown: true,
    basePath: "/",
    onFiltersChange: () => undefined,
    onRefresh: () => undefined,
    onPatch: () => undefined,
    onDelete: () => undefined,
    ...overrides,
  };
}

describe("sessions view", () => {
  it("skips patching when the label is unchanged", () => {
    const container = document.createElement("div");
    const onPatch = vi.fn();
    const row = createRow({ label: "Alpha" });

    render(
      renderSessions(
        createProps({
          result: createResult([row]),
          onPatch,
        }),
      ),
      container,
    );

    const input = container.querySelector("input") as HTMLInputElement | null;
    expect(input).not.toBeNull();
    input?.dispatchEvent(new Event("change", { bubbles: true }));

    expect(onPatch).not.toHaveBeenCalled();
  });

  it("clears labels when the input is empty", () => {
    const container = document.createElement("div");
    const onPatch = vi.fn();
    const row = createRow({ label: "Alpha" });

    render(
      renderSessions(
        createProps({
          result: createResult([row]),
          onPatch,
        }),
      ),
      container,
    );

    const input = container.querySelector("input") as HTMLInputElement | null;
    expect(input).not.toBeNull();
    if (!input) return;
    input.value = "   ";
    input.dispatchEvent(new Event("change", { bubbles: true }));

    expect(onPatch).toHaveBeenCalledWith("session-1", { label: null });
  });
});
