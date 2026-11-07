// AG-UI の SSE の本文を、イベントの列にする（テストの観察と書き換えで使う）。
import type { BaseEvent } from "@ag-ui/core";

export type AgentEvent = BaseEvent & Record<string, any>;

export function parseSse(text: string): AgentEvent[] {
  return text
    .split("\n\n")
    .map((b) => b.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n"))
    .filter(Boolean)
    .map((d) => JSON.parse(d) as AgentEvent);
}
