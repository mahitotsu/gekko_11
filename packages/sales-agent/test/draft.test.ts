import { describe, expect, it } from "vitest";
import { applicationOf, intentOf } from "../src/draft.ts";

const plans = [
  { id: "fixed-60", name: "確定年金 10年・年額60万円", kind: "fixed", benefit: 600_000, monthly: 20_000 },
  { id: "life-120", name: "終身年金・年額120万円", kind: "lifetime", benefit: 1_200_000, monthly: 60_000 },
];
const offer = { offerJws: "jws", offerSet: { customer: "alice", plans }, offerSetId: "set-1", nonce: "n-1", expiresAt: 1 };

describe("書類の組み立て", () => {
  it("LLM が決めた案の番号と意向に、提示の識別子と nonce を足す", () => {
    expect(intentOf("alice", offer, "fixed-60", "老後に備えたい")).toEqual({
      customer: "alice", offerSetId: "set-1", planId: "fixed-60", wish: "老後に備えたい", nonce: "n-1", expiresAt: 1,
    });
  });

  it("申込書には、案の中身と、意向確認の署名の値を入れる", () => {
    expect(applicationOf("alice", offer, "fixed-60", "sig")).toEqual({
      customer: "alice", plan: plans[0], offerSetId: "set-1", intentSignature: "sig", nonce: "n-1", expiresAt: 1,
    });
  });

  it("示していない案では作らない", () => {
    expect(() => intentOf("alice", offer, "life-240", "")).toThrow();
    // 振返りの欄は、あるときだけ入れる（ない欄は、署名する内容に現れない）
    expect(intentOf("alice", offer, "fixed-60", "最終", undefined, { initialWish: "最初", changeNote: "違い" })).toMatchObject({ initialWish: "最初", changeNote: "違い", wish: "最終" });
    expect(Object.keys(intentOf("alice", offer, "fixed-60", "最終", undefined, {}))).not.toContain("initialWish");
  });
});
