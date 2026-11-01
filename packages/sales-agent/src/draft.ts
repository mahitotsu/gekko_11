// 申込書の案。顧客が選んだ案から、意向確認と申込みの内容と、説明文を作る（3 章の 3 段、D-27）。
// LLM を通さない決まった処理である。顧客のアプリは、説明文ではなく、ここで作った内容そのものから確認画面を描き、署名する（D23）。
import type { Plan } from "./scripted.ts";

export interface OfferForDraft {
  offerSet: { plans: Plan[] };
  offerSetId: string;
  nonce: string;
  expiresAt: number;
}

export interface Draft {
  /** 意向確認の内容（署名する）。 */
  intent: { customer: string; offerSetId: string; planId: string; wish: string; nonce: string; expiresAt: number };
  /** 申込みの内容（署名する）。intentSignature は、顧客のアプリが意向確認に署名した後に入れる。 */
  application: { customer: string; plan: Plan; offerSetId: string; nonce: string; expiresAt: number };
  /** 営業 AI エージェントの説明文。署名しない。 */
  summary: string;
}

export function draft(customer: string, offer: OfferForDraft, planId: string, wish: string): Draft {
  const plan = offer.offerSet.plans.find((p) => p.id === planId);
  if (!plan) throw new Error(`示した案に ${planId} がない`);
  const { offerSetId, nonce, expiresAt } = offer;
  return {
    intent: { customer, offerSetId, planId, wish, nonce, expiresAt },
    application: { customer, plan, offerSetId, nonce, expiresAt },
    summary: describe(plan),
  };
}

export const describe = (plan: Plan) =>
  `「${plan.name}」（年金の年額 ${plan.benefit.toLocaleString("ja-JP")} 円、月額の保険料 ${plan.monthly.toLocaleString("ja-JP")} 円）で、意向確認書と申込書を用意しました。内容を確かめて、署名してください。`;
