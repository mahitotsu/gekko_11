import { describe, expect, it } from "vitest";
import { draft } from "../src/draft.ts";

const plans = [
  { id: "fixed-60", name: "確定年金 10年・年額60万円", kind: "fixed", benefit: 600_000, monthly: 20_000 },
  { id: "life-120", name: "終身年金・年額120万円", kind: "lifetime", benefit: 1_200_000, monthly: 60_000 },
];
const offer = { offerSet: { plans }, offerSetId: "set-1", nonce: "n-1", expiresAt: 1 };

describe("申込書の案", () => {
  it("選んだ案から、意向確認と申込みの内容を作る", () => {
    const d = draft("alice", offer, "fixed-60", "老後に備えたい");
    expect(d.intent).toEqual({ customer: "alice", offerSetId: "set-1", planId: "fixed-60", wish: "老後に備えたい", nonce: "n-1", expiresAt: 1 });
    expect(d.application).toEqual({ customer: "alice", plan: plans[0], offerSetId: "set-1", nonce: "n-1", expiresAt: 1 });
    expect(d.summary).toContain("月額の保険料 20,000 円");
  });

  it("示していない案では作らない", () => {
    expect(() => draft("alice", offer, "life-240", "")).toThrow();
  });
});
