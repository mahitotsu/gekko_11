// AG-UI の受け口（D-29）。AG-UI 1.0 の HTTP と SSE: POST で RunAgentInput を受け、SSE で 1 回分のイベントを返す。
// 回は、営業 AI エージェントが画面側の道具を呼んだところ（顧客の答えを待つ）か、番が終わったところで閉じる。
// 顧客の答えは、次の回の tool message で届く。トークンは token-guard が確かめ（G20）、会話は本人（sub）に結び付ける。
import { contentToText, EventType, type BaseEvent } from "@ag-ui/core";
import { RunAgentInputSchema } from "@ag-ui/core/schemas";
import type { Context } from "hono";
import { stream } from "hono/streaming";
import { claimsOf } from "./claims.ts";
import { threadFor, type Thread } from "./thread.ts";

/** SSE の 1 件。data に、AG-UI のイベントを 1 つ、JSON で入れる（AG-UI 1.0 の HTTP と SSE）。 */
const sse = (event: object) => `data: ${JSON.stringify(event)}\n\n`;

export async function handleRun(c: Context, start: (t: Thread) => void) {
  const parsed = RunAgentInputSchema.safeParse(await c.req.json().catch(() => undefined));
  if (!parsed.success) return c.json({ error: "RunAgentInput の形が違う" }, 400);
  const input = parsed.data;
  let thread: Thread;
  try {
    const claims = claimsOf(c.req.header("x-auth-claims"));
    thread = threadFor(input.threadId, claims.sub, start);
  } catch (e) {
    return c.json({ error: (e as Error).message }, 403);
  }
  thread.ctx = c.req.header("x-auth-ctx") ?? "";
  thread.claims = c.req.header("x-auth-claims") ?? "";

  const waiting = thread.waitingFor;
  if (waiting) {
    const reply = input.messages.find((m) => m.role === "tool" && m.toolCallId === waiting);
    if (!reply) return c.json({ error: `道具の呼び出し ${waiting} への答え（tool message）がない` }, 409);
    thread.answer(waiting, typeof reply.content === "string" ? reply.content : JSON.stringify(reply.content));
  } else {
    const said = [...input.messages].reverse().find((m) => m.role === "user");
    if (!said) return c.json({ error: "顧客の文（user message）がない" }, 400);
    thread.tell(contentToText(said.content) ?? "");
  }

  c.header("content-type", "text/event-stream");
  c.header("cache-control", "no-cache");
  return stream(c, async (s) => {
    const base = { threadId: input.threadId, runId: input.runId };
    await s.write(sse({ type: EventType.RUN_STARTED, ...base }));
    for await (const item of thread.drain()) {
      if ("pause" in item) return void (await s.write(sse({ type: EventType.RUN_FINISHED, ...base })));
      if ("end" in item) {
        return void (await s.write(sse(item.error ? { type: EventType.RUN_ERROR, message: item.error } : { type: EventType.RUN_FINISHED, ...base })));
      }
      await s.write(sse(item as BaseEvent));
    }
  });
}
