// 顧客のアプリが、ブラウザの中で確かめること（scenarios の 2-3 の顧客のアプリの表）。
// D21: ID トークン、D22: 案の署名、D23: 確認画面を署名する内容から作る。画面の部品から切り離し、単体テストで確かめる。
import { jwtVerify, type JWTVerifyGetKey } from "jose";
import { challengeOf } from "./codec.ts";

export interface Plan {
  id: string;
  name: string;
  kind: string;
  benefit: number;
  monthly: number;
}

/** 営業 AI エージェントが運んできた提示（事務サービスの get_offers の結果）。 */
export interface Offer {
  offerJws: string;
  offerSet: { customer: string; plans: Plan[] };
  offerSetId: string;
  nonce: string;
  expiresAt: number;
}

/** D21: ID トークンの署名、iss、宛先（顧客のアプリ）、期限、nonce を確かめ、本人を返す。 */
export async function verifyIdToken(
  idToken: string,
  keys: JWTVerifyGetKey,
  expect: { issuer: string; clientId: string; nonce: string },
): Promise<{ sub: string }> {
  const { payload } = await jwtVerify(idToken, keys, { issuer: expect.issuer, audience: expect.clientId, algorithms: ["RS256"], requiredClaims: ["sub", "exp"] });
  if (payload.nonce !== expect.nonce) throw new Error("ID トークンの nonce が、このログインのものではない");
  return { sub: payload.sub! };
}

/**
 * D22: 提示の、保険会社の署名を確かめ、署名された中身だけを返す。営業 AI エージェントが運んだ案の一覧は使わない。
 * 運ばれた一覧が署名された中身と違えば、tampered を立てる（画面に、すり替えを知らせる）。
 */
export async function verifyOffer(offer: Offer, keys: JWTVerifyGetKey, sub: string): Promise<{ offer: Offer; tampered: boolean }> {
  const { payload } = await jwtVerify(offer.offerJws, keys, { issuer: "insurer-backend", typ: "offer+jwt", algorithms: ["ES256"] });
  const signed = payload as unknown as { customer: string; plans: Plan[]; offerSetId: string; nonce: string; exp: number };
  if (signed.customer !== sub) throw new Error("提示が、ログインした本人宛てではない");
  if ((await challengeOf({ customer: signed.customer, plans: signed.plans })) !== signed.offerSetId) {
    throw new Error("提示集合の識別子が、案の内容と一致しない");
  }
  const verified: Offer = {
    offerJws: offer.offerJws,
    offerSet: { customer: signed.customer, plans: signed.plans },
    offerSetId: signed.offerSetId,
    nonce: signed.nonce,
    expiresAt: signed.exp,
  };
  const tampered =
    (await challengeOf(offer.offerSet)) !== (await challengeOf(verified.offerSet)) ||
    offer.offerSetId !== verified.offerSetId ||
    offer.nonce !== verified.nonce;
  return { offer: verified, tampered };
}

/** 営業 AI エージェントが作った申込書の案（/prepare の結果）。 */
export interface Draft {
  intent: { customer: string; offerSetId: string; planId: string; wish: string; nonce: string; expiresAt: number };
  application: { customer: string; plan: Plan; offerSetId: string; nonce: string; expiresAt: number };
  summary: string;
}

/** 確認画面の 1 行。 */
export interface Row {
  label: string;
  value: string;
  key: string;
}

/** D23: 確認画面は、署名する内容そのものから作る。営業 AI エージェントの説明文は使わない。 */
export function confirmationOf(draft: Draft): Row[] {
  const { intent, application } = draft;
  const yen = (n: number) => `${n.toLocaleString("ja-JP")} 円`;
  return [
    { key: "customer", label: "契約者", value: application.customer },
    { key: "plan-name", label: "申し込む案", value: application.plan.name },
    { key: "plan-id", label: "案の番号", value: application.plan.id },
    { key: "benefit", label: "年金の年額", value: yen(application.plan.benefit) },
    { key: "monthly", label: "月額の保険料", value: yen(application.plan.monthly) },
    { key: "intent-plan", label: "意向確認で選んだ案の番号", value: intent.planId },
    { key: "wish", label: "意向", value: intent.wish },
  ];
}
