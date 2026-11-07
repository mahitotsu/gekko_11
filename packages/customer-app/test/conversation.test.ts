import { describe, expect, it } from "vitest";
import { initialState, isLatestOfKind, reducer, type Action, type CardData, type State } from "../web/conversation.ts";

const apply = (actions: Action[], from: State = initialState) => actions.reduce(reducer, from);
const ask: CardData = { kind: "ask", toolCallId: "t1", question: "q", options: ["a"] };

describe("カードの積み重ね（D-34）", () => {
  it("始め直すと、最初のカードだけになり、前の状態を持ち越さない", () => {
    const s = apply([{ type: "reset" }, { type: "text", content: "x" }, { type: "card", data: ask }, { type: "submitted", nonce: "n" }, { type: "reset" }]);
    expect(s.cards.map((c) => c.data.kind)).toEqual(["start"]);
    expect([s.submitted, s.submitting, s.pendingText]).toEqual(["", false, []]);
    // 同じ番号を使うと、React が前のカードの入力の状態を使い回し、入力欄が出ない
    expect(s.cards[0]!.id).toBeGreaterThan(2);
  });

  it("ためた文は次のカードに入れ、次のカードには持ち越さない", () => {
    const s = apply([{ type: "reset" }, { type: "text", content: "説明" }, { type: "card", data: ask }, { type: "card", data: { kind: "continue" } }]);
    expect(s.cards[1]!.notes).toEqual(["説明"]);
    expect(s.cards[2]!.notes).toEqual([]);
    expect(s.lastText).toBe("説明");
  });

  it("段階は、案と書類と完了で進み、質問では動かない", () => {
    const offer = { offerSet: { plans: [] } } as never;
    let s = apply([{ type: "reset" }, { type: "card", data: ask }]);
    expect(s.step).toBe("consult");
    s = reducer(s, { type: "card", data: { kind: "offers", toolCallId: "t", offer, verified: true, tampered: false } });
    expect([s.step, s.offer]).toEqual(["offers", offer]);
    s = reducer(s, { type: "card", data: ask });
    expect(s.step).toBe("offers");
    s = reducer(s, { type: "card", data: { kind: "finish" } });
    expect(s.step).toBe("reconcile");
  });

  it("テストの目印を付けるのは、同じ種類の最新のカードだけである", () => {
    const s = apply([{ type: "reset" }, { type: "card", data: ask }, { type: "card", data: { ...ask, toolCallId: "t2" } as CardData }]);
    expect(isLatestOfKind(s.cards, s.cards[1]!)).toBe(false);
    expect(isLatestOfKind(s.cards, s.cards[2]!)).toBe(true);
    expect(isLatestOfKind(s.cards, s.cards[0]!)).toBe(true);
  });
});
