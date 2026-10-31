import { describe, expect, it } from "vitest";
import { claimsOf } from "../src/claims.ts";
import { mostExpensiveWithin } from "../src/choose.ts";

const plans = [
  { id: "fixed-60", name: "", kind: "fixed", benefit: 600_000, monthly: 20_000 },
  { id: "life-120", name: "", kind: "lifetime", benefit: 1_200_000, monthly: 60_000 },
  { id: "life-240", name: "", kind: "lifetime", benefit: 2_400_000, monthly: 120_000 },
];

describe("乗っ取られた営業 AI エージェントの選び方（A8）", () => {
  it("取決めの範囲で、最も保険料が高い案を選ぶ", () => {
    const terms = { type: "insurance_application", kinds: ["fixed", "lifetime"], maxBenefit: 1_200_000 };
    expect(mostExpensiveWithin(plans, terms)?.id).toBe("life-120");
    expect(mostExpensiveWithin(plans, undefined)?.id).toBe("life-240");
  });

  it("token-guard が渡す主張を読む", () => {
    const header = Buffer.from(JSON.stringify({ claims: { sub: "alice" }, peer: {} })).toString("base64url");
    expect(claimsOf(header).sub).toBe("alice");
    expect(() => claimsOf(undefined)).toThrow();
  });
});
