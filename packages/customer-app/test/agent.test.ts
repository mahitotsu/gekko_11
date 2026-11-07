import { describe, expect, it } from "vitest";
import { createAgent, statusOf } from "../web/agent.ts";

const base = { threadId: "t", runId: "r" };
const sse = (events: object[]) =>
  new Response(events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join(""), { status: 200, headers: { "content-type": "text/event-stream" } });

const toolRun = [
  { type: "RUN_STARTED", ...base },
  { type: "TEXT_MESSAGE_START", messageId: "m1", role: "assistant" },
  { type: "TEXT_MESSAGE_CONTENT", messageId: "m1", delta: "説明" },
  { type: "TEXT_MESSAGE_END", messageId: "m1" },
  { type: "TOOL_CALL_START", toolCallId: "c1", toolCallName: "ask_customer" },
  { type: "TOOL_CALL_ARGS", toolCallId: "c1", delta: JSON.stringify({ question: "q", options: ["a"] }) },
  { type: "TOOL_CALL_END", toolCallId: "c1" },
  { type: "RUN_FINISHED", ...base },
];

const handlers = () => {
  const seen = { texts: [] as string[], tools: [] as unknown[][], errors: [] as string[] };
  return {
    seen,
    h: {
      onText: (t: string) => seen.texts.push(t),
      onToolCall: (id: string, name: string, args: unknown) => seen.tools.push([id, name, args]),
      onRunError: (m: string) => seen.errors.push(m),
    },
  };
};

describe("AG-UI の接続（@ag-ui/client。D-29）", () => {
  it("文と道具の呼び出しを渡し、要求ごとに、そのときの proof を付ける", async () => {
    const sent: { headers: Record<string, string>; body: any }[] = [];
    let n = 0;
    const agent = createAgent(
      "http://agent.test/agui",
      async () => ({ authorization: "DPoP a", dpop: `proof-${++n}` }),
      (async (_url: string, init: RequestInit) => {
        sent.push({ headers: init.headers as Record<string, string>, body: JSON.parse(init.body as string) });
        return sse(toolRun);
      }) as typeof fetch,
    );
    const { seen, h } = handlers();
    agent.say("希望");
    await agent.run(h);
    expect(seen.texts).toEqual(["説明"]);
    expect(seen.tools).toEqual([["c1", "ask_customer", { question: "q", options: ["a"] }]]);

    // 顧客の答えは、次の回の tool message で届く。営業 AI エージェントは、道具の呼び出しの番号で探す
    agent.answer("c1", '{"answer":"a"}');
    await agent.run(handlers().h);
    expect(sent.map((s) => s.headers.dpop)).toEqual(["proof-1", "proof-2"]);
    expect(sent[0]!.headers.authorization).toBe("DPoP a");
    expect(sent[1]!.body.messages.find((m: any) => m.role === "tool")).toMatchObject({ toolCallId: "c1", content: '{"answer":"a"}' });
    expect(sent[0]!.body.tools.map((t: any) => t.name)).toContain("present_offers");
    expect(sent[1]!.body.threadId).toBe(sent[0]!.body.threadId);
  });

  it("断られると、状態の分かる失敗になる（401 なら、更新して送り直す）", async () => {
    const agent = createAgent(
      "http://agent.test/agui",
      async () => ({}),
      (async () => new Response('{"error":"expired"}', { status: 401, headers: { "content-type": "application/json" } })) as typeof fetch,
    );
    agent.say("希望");
    const failure = await agent.run(handlers().h).then(() => undefined, (e: unknown) => e);
    expect(statusOf(failure)).toBe(401);
  });

  it("送り直せる（断られた回の後でも、同じ会話で次の回を走らせられる）", async () => {
    let n = 0;
    const agent = createAgent(
      "http://agent.test/agui",
      async () => ({}),
      (async () => (n++ === 0 ? new Response("{}", { status: 401, headers: { "content-type": "application/json" } }) : sse(toolRun))) as typeof fetch,
    );
    const { seen, h } = handlers();
    agent.say("希望");
    await agent.run(h).catch(() => undefined);
    await agent.run(h);
    expect(seen.tools).toHaveLength(1);
  });

  it("営業 AI エージェントの失敗の知らせを渡す", async () => {
    const agent = createAgent(
      "http://agent.test/agui",
      async () => ({}),
      (async () => sse([{ type: "RUN_STARTED", ...base }, { type: "RUN_ERROR", message: "止まりました" }])) as typeof fetch,
    );
    const { seen, h } = handlers();
    agent.say("希望");
    await agent.run(h).catch(() => undefined);
    expect(seen.errors).toEqual(["止まりました"]);
  });
});
