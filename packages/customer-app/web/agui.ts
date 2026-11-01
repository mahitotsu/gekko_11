// AG-UI の小さな受け手（D-29）。AG-UI 1.0 の HTTP と SSE: RunAgentInput を POST し、SSE の data の行を、届いた順に読む。
// 営業 AI エージェントは token-guard の後ろにいるので、回ごとに、トークン A と DPoP の proof を付ける。
import type { BaseEvent, Message, Tool } from "@ag-ui/core";

export interface RunInput {
  threadId: string;
  runId: string;
  messages: Message[];
  tools: Tool[];
  state: Record<string, never>;
  context: never[];
  forwardedProps: Record<string, never>;
}

export type AgentEvent = BaseEvent & Record<string, any>;

/** 1 回分を走らせ、イベントを 1 つずつ渡す。RUN_FINISHED か RUN_ERROR で終わる。 */
export async function runOnce(url: string, headers: Record<string, string>, input: RunInput, onEvent: (e: AgentEvent) => void): Promise<void> {
  const res = await fetch(url, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json", accept: "text/event-stream" },
    body: JSON.stringify(input),
  });
  if (!res.ok || !res.body) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(`営業 AI エージェントが断った: ${body.error ?? res.status}`);
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    let at: number;
    while ((at = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, at);
      buffer = buffer.slice(at + 2);
      const data = block.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
      if (data) onEvent(JSON.parse(data) as AgentEvent);
    }
  }
}

/** SSE の本文を、イベントの列にする（テストの書き換えでも使う）。 */
export function parseSse(text: string): AgentEvent[] {
  return text
    .split("\n\n")
    .map((b) => b.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n"))
    .filter(Boolean)
    .map((d) => JSON.parse(d) as AgentEvent);
}

/** 画面側の道具（RunAgentInput.tools）。営業 AI エージェントが呼び、この画面が顧客の答えを返す。 */
export const FRONTEND_TOOLS: Tool[] = [
  { name: "ask_customer", description: "顧客に、選択肢のある質問をする", parameters: { type: "object", properties: { question: { type: "string" }, options: { type: "array", items: { type: "string" } } }, required: ["question", "options"] } },
  { name: "present_offers", description: "保険会社の署名つきの提示を示し、顧客に 1 つ選んでもらう", parameters: { type: "object", properties: { message: { type: "string" }, offer: { type: "object" } }, required: ["offer"] } },
  { name: "present_intent", description: "意向確認書面を示し、顧客に署名してもらう（署名 1/2）", parameters: { type: "object", properties: { intent: { type: "object" } }, required: ["intent"] } },
  { name: "present_application", description: "申込書を示し、顧客に署名してもらう（署名 2/2）", parameters: { type: "object", properties: { application: { type: "object" } }, required: ["application"] } },
];
