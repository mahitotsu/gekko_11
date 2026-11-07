// 営業 AI エージェントとの AG-UI（D-29）。@ag-ui/client を使い、要求ごとに、トークン A と DPoP の proof を付ける。
// 営業 AI エージェントは token-guard の後ろにいる。
import { HttpAgent } from "@ag-ui/client";
import type { Tool } from "@ag-ui/core";

/** 画面側の道具（RunAgentInput.tools）。営業 AI エージェントが呼び、この画面が顧客の答えを返す。 */
export const FRONTEND_TOOLS: Tool[] = [
  { name: "ask_customer", description: "顧客に、選択肢のある質問をする", parameters: { type: "object", properties: { question: { type: "string" }, options: { type: "array", items: { type: "string" } } }, required: ["question", "options"] } },
  { name: "present_offers", description: "保険会社の署名つきの提示を示し、顧客に 1 つ選んでもらう", parameters: { type: "object", properties: { message: { type: "string" }, reasons: { type: "object" }, offer: { type: "object" } }, required: ["offer"] } },
  { name: "present_intent", description: "意向確認書面を示し、顧客に署名してもらう（署名 1/2）", parameters: { type: "object", properties: { intent: { type: "object" } }, required: ["intent"] } },
  { name: "present_application", description: "申込書を示し、顧客に署名してもらう（署名 2/2）", parameters: { type: "object", properties: { application: { type: "object" } }, required: ["application"] } },
];

export interface AgentHandlers {
  onText(content: string): void;
  onToolCall(id: string, name: string, args: Record<string, unknown>): void;
  onRunError(message: string): void;
}

/** 断られた要求の状態。401 なら、更新して送り直す。 */
export const statusOf = (e: unknown): number | undefined => (e as { status?: number } | undefined)?.status;

export function createAgent(url: string, headers: () => Promise<Record<string, string>>, fetcher: typeof fetch = fetch.bind(globalThis)) {
  const agent = new HttpAgent({
    url,
    threadId: crypto.randomUUID(),
    // 要求ごとに proof を作る。送り直すときも、そのときの A を使う
    fetch: async (target, init) => fetcher(target, { ...init, headers: { ...(init.headers as Record<string, string>), ...(await headers()) } }),
  });
  return {
    /** 1 回分を走らせる。営業 AI エージェントの文と道具の呼び出しを、届いた順に渡す。 */
    async run(handlers: AgentHandlers) {
      await agent.runAgent(
        { tools: FRONTEND_TOOLS, runId: crypto.randomUUID() },
        {
          onTextMessageEndEvent: ({ textMessageBuffer }) => handlers.onText(textMessageBuffer),
          onToolCallEndEvent: ({ event, toolCallName, toolCallArgs }) => handlers.onToolCall(event.toolCallId, toolCallName, toolCallArgs),
          onRunErrorEvent: ({ event }) => handlers.onRunError(event.message),
        },
      );
    },
    say: (content: string) => agent.addMessage({ id: crypto.randomUUID(), role: "user", content }),
    answer: (toolCallId: string, content: string) => agent.addMessage({ id: crypto.randomUUID(), role: "tool", toolCallId, content }),
    abort: () => agent.abortRun(),
  };
}

export type Agent = ReturnType<typeof createAgent>;
