import { describe, expect, it } from "vitest";
import { scriptedTurn } from "../src/scripted.ts";
import { Thread } from "../src/thread.ts";

const plans = [{ id: "fixed-60", name: "確定年金 10年・年額60万円", kind: "fixed", benefit: 600_000, monthly: 20_000 }];
const offer = { offerJws: "jws", offerSet: { customer: "alice", plans }, offerSetId: "set-1", nonce: "n-1", expiresAt: 1 };

/** 事務サービスの代わり。呼ばれた道具と引数を残す。 */
function fakeMcp(calls: { name: string; args?: Record<string, unknown> }[]) {
  return async (_ctx: string, name: string, args?: Record<string, unknown>) => {
    calls.push({ name, args });
    if (name === "get_offers") return { isError: false, body: offer };
    return { isError: false, body: { ok: true, contract: { contractId: "C-1" } } };
  };
}

/** 次の区切りまでのイベントを集める。 */
async function nextRun(t: Thread) {
  const items = [];
  for await (const item of t.drain()) items.push(item);
  return items as Record<string, any>[];
}

const toolCall = (items: Record<string, any>[]) => ({
  id: items.find((e) => e.type === "TOOL_CALL_START")?.toolCallId as string,
  name: items.find((e) => e.type === "TOOL_CALL_START")?.toolCallName as string,
  args: JSON.parse(items.find((e) => e.type === "TOOL_CALL_ARGS")?.delta ?? "{}"),
});

describe("台本の会話（AG-UI のイベント）", () => {
  it("質問 → 案 → 意向確認書面 → 申込書 → 提出の順に、画面側の道具を呼び、回を区切る", async () => {
    const t = new Thread("th-1", "alice");
    const calls: { name: string; args?: Record<string, unknown> }[] = [];
    const done = scriptedTurn(t, "老後に備えたい", fakeMcp(calls)).then(() => t.end());

    let c = toolCall(await nextRun(t));
    expect(c.name).toBe("ask_customer");
    t.answer(c.id, "終身年金");

    c = toolCall(await nextRun(t));
    expect(c.name).toBe("present_offers");
    expect(c.args.offer.offerSetId).toBe("set-1"); // 提示は、決まった処理が足す
    t.answer(c.id, JSON.stringify({ planId: "fixed-60" }));

    c = toolCall(await nextRun(t));
    expect(c.name).toBe("present_intent");
    expect(c.args.intent).toMatchObject({ customer: "alice", planId: "fixed-60", nonce: "n-1" });
    t.answer(c.id, JSON.stringify({ assertion: { response: { signature: "sig-1" } } }));

    c = toolCall(await nextRun(t));
    expect(c.name).toBe("present_application");
    expect(c.args.application.intentSignature).toBe("sig-1"); // 署名の値は、決まった処理が入れる
    t.answer(c.id, JSON.stringify({ assertion: { response: { signature: "sig-2" } } }));

    const last = await nextRun(t);
    await done;
    expect(last.at(-1)).toEqual({ end: true, error: undefined });
    expect(last.find((e) => e.type === "TEXT_MESSAGE_CONTENT")?.delta).toContain("C-1");
    expect(calls.map((x) => x.name)).toEqual(["get_offers", "submit_application"]);
    expect(calls[1]?.args).toMatchObject({ application: { plan: plans[0], intentSignature: "sig-1" } });
  });

  it("書類への署名を断ると、提出しない", async () => {
    const t = new Thread("th-2", "alice");
    const calls: { name: string }[] = [];
    const done = scriptedTurn(t, "案を見たい", fakeMcp(calls)).then(() => t.end());
    let c = toolCall(await nextRun(t));
    t.answer(c.id, "確定年金");
    c = toolCall(await nextRun(t));
    t.answer(c.id, JSON.stringify({ planId: "fixed-60" }));
    c = toolCall(await nextRun(t));
    t.answer(c.id, JSON.stringify({ declined: true }));
    await nextRun(t);
    await done;
    expect(calls.map((x) => x.name)).toEqual(["get_offers"]);
  });
});
