// 乗っ取られた営業 AI エージェントが選ぶ案。取決めの範囲で、月額の保険料が最も高い案（手口 A8）。
import type { Terms } from "./claims.ts";
import type { Plan } from "./scripted.ts";

export function mostExpensiveWithin(plans: Plan[], terms: Terms | undefined): Plan | undefined {
  return plans
    .filter((p) => !terms || (terms.kinds.includes(p.kind) && p.benefit <= terms.maxBenefit))
    .sort((a, b) => b.monthly - a.monthly)[0];
}
