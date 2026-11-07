import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { scriptedTurn } from "../src/scripted.ts";
import { digest, redact, Thread } from "../src/thread.ts";

const plans = [{ id: "fixed-60", name: "確定年金 10年・年額60万円", kind: "fixed", benefit: 600_000, monthly: 20_000 }];
const offer = { offerJws: "jws", offerSet: { customer: "alice", plans }, offerSetId: "set-1", nonce: "n-1", expiresAt: 1 };

/** 事務サービスの代わり。呼ばれた道具と引数を残す。 */
function fakeMcp(calls: { name: string; args?: Record<string, unknown> }[]) {
  return async (_ctx: string, name: string, args?: Record<string, unknown>) => {
    calls.push({ name, args });
    if (name === "issue_offer") return { isError: false, body: offer };
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

describe("振返りと推奨の理由（P-17）", () => {
  it("最初の文を当初の意向として残し、理由を提示に足す", async () => {
    const t = new Thread("th-review", "alice");
    t.tell("年に 80 万円ほしい");
    t.tell("掛け金を抑えたい");
    t.setOffer(offer);
    const shown = t.frontend("present_offers", { message: "説明", reasons: { "fixed-60": "意向に近い" } });
    let c = toolCall(await nextRun(t));
    expect(c.args.reasons).toEqual({ "fixed-60": "意向に近い" });
    t.answer(c.id, JSON.stringify({ planId: "fixed-60", plan: plans[0] }));
    await shown;
    void t.frontend("present_intent", { planId: "fixed-60", wish: "掛け金を抑えて受け取りたい", changeNote: "額より掛け金を優先した" });
    c = toolCall(await nextRun(t));
    expect(c.args.intent).toMatchObject({ initialWish: "年に 80 万円ほしい", wish: "掛け金を抑えて受け取りたい", changeNote: "額より掛け金を優先した" });
  });

  it("案のカードの自由入力は、選んだ案でなく、文として渡す", async () => {
    const t = new Thread("th-other", "alice");
    t.setOffer(offer);
    const shown = t.frontend("present_offers", { message: "説明" });
    const c = toolCall(await nextRun(t));
    t.answer(c.id, JSON.stringify({ answer: "掛け金を抑えたい" }));
    expect(await shown).toBe("掛け金を抑えたい");
    expect(t.chosen).toBeUndefined();
  });
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
    expect(calls.map((x) => x.name)).toEqual(["issue_offer", "submit_application"]);
    expect(calls[1]?.args).toMatchObject({ application: { plan: plans[0], intentSignature: "sig-1" } });
  });

  it("自由入力の答えで進み、JSON として読める文（null など）でも止まらない", async () => {
    const t = new Thread("th-free", "alice");
    const calls: { name: string; args?: Record<string, unknown> }[] = [];
    const done = scriptedTurn(t, "個人年金の契約を考えています", fakeMcp(calls)).then(() => t.end());
    // 「契約」の語を含む希望でも、一覧の照会にならず、質問へ進む
    let c = toolCall(await nextRun(t));
    expect(c.name).toBe("ask_customer");
    t.answer(c.id, JSON.stringify({ answer: "10 年だけ受け取りたい" }));
    c = toolCall(await nextRun(t));
    t.answer(c.id, JSON.stringify({ planId: "fixed-60" }));
    c = toolCall(await nextRun(t));
    expect(JSON.stringify(c.args)).toContain("10 年だけ受け取りたい");
    t.answer(c.id, JSON.stringify({ declined: true }));
    await done;

    for (const text of ["null", "123", "true", "\"文\""]) {
      const n = new Thread(`th-${text}`, "alice");
      const pending = n.frontend("ask_customer", { question: "質問", options: ["a", "b"] });
      const q = toolCall(await nextRun(n));
      n.answer(q.id, text);
      expect(await pending).toBe(text);
    }
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
    expect(calls.map((x) => x.name)).toEqual(["issue_offer"]);
  });
});

describe("会話の記録（D-32）", () => {
  it("トークン、署名の値、提示の JWS を伏せる", () => {
    const out = redact({ application: { plan: { id: "fixed-60" }, intentSignature: "sig" }, assertion: { response: { signature: "s" } }, offerJws: "jws", text: "老後に備えたい" }) as Record<string, any>;
    expect(out).toEqual({ application: { plan: { id: "fixed-60" }, intentSignature: "（伏せた）" }, assertion: "（伏せた）", offerJws: "（伏せた）", text: "老後に備えたい" });
  });
});

describe("書類のハッシュ", () => {
  it("JCS で正規化した内容の SHA-256（鍵の順に依らない）", () => {
    expect(digest({ b: 1, a: "あ" })).toBe(digest({ a: "あ", b: 1 }));
    expect(digest({ a: "あ", b: 1 })).toBe(createHash("sha256").update('{"a":"あ","b":1}').digest("base64url"));
  });
});
