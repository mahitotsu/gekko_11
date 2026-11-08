// 書類の組み立て（3 章の 3 段、D-27）。LLM が決めた値（案の番号、意向の文）に、決まった処理が、直前の提示の識別子と
// 意向確認の署名の値を足す。長い識別子や署名の値を、LLM に写させない。顧客のアプリは、この内容そのものから画面を描いて署名する（G23）。
import type { Plan } from "./scripted.ts";

export interface Offer {
  offerJws: string;
  offerSet: { customer: string; plans: Plan[] };
  offerSetId: string;
  nonce: string;
  expiresAt: number;
}

export interface Intent {
  customer: string;
  offerSetId: string;
  planId: string;
  /** 最終の意向。LLM が書く。 */
  wish: string;
  /** 顧客の最初の文。決まった処理が入れ、LLM には書かせない（振返り。P-17）。 */
  initialWish?: string;
  /** 最初の希望と最終の意向の違いと、その経緯。LLM が書く。 */
  changeNote?: string;
  nonce: string;
  expiresAt: number;
}

export interface Application {
  customer: string;
  plan: Plan;
  offerSetId: string;
  intentSignature: string;
  nonce: string;
  expiresAt: number;
}

/** 案の番号から案の中身を引く。顧客が画面で選んだ案（chosen）があれば、その中身を使う。 */
const planIn = (offer: Offer, planId: string, chosen?: Plan) => {
  const plan = chosen?.id === planId ? chosen : offer.offerSet.plans.find((p) => p.id === planId);
  if (!plan) throw new Error(`示した案に ${planId} がない`);
  return plan;
};

export function intentOf(customer: string, offer: Offer, planId: string, wish: string, chosen?: Plan, review: { initialWish?: string; changeNote?: string } = {}): Intent {
  planIn(offer, planId, chosen);
  return {
    customer,
    offerSetId: offer.offerSetId,
    planId,
    wish,
    ...(review.initialWish ? { initialWish: review.initialWish } : {}),
    ...(review.changeNote ? { changeNote: review.changeNote } : {}),
    nonce: offer.nonce,
    expiresAt: offer.expiresAt,
  };
}

export function applicationOf(customer: string, offer: Offer, planId: string, intentSignature: string, chosen?: Plan): Application {
  return { customer, plan: planIn(offer, planId, chosen), offerSetId: offer.offerSetId, intentSignature, nonce: offer.nonce, expiresAt: offer.expiresAt };
}
