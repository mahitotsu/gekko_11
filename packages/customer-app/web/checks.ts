// 顧客のアプリが、ブラウザの中で確かめること（scenarios の 2-3 の顧客のアプリの表）。
// D21: ID トークン、D22: 案の署名、D23: 確認画面を署名する内容から作る。画面の部品から切り離し、単体テストで確かめる。
import { decodeJwt, jwtVerify, type JWTVerifyGetKey } from "jose";
import { challengeOf } from "./codec.ts";

export interface Plan {
  id: string;
  name: string;
  kind: string;
  benefit: number;
  monthly: number;
}

/** 営業 AI エージェントが運んできた提示（事務サービスの issue_offer の結果）。 */
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

/** 営業 AI エージェントが示す意向確認書面（present_intent の引数）。 */
export interface Intent {
  customer: string;
  offerSetId: string;
  planId: string;
  wish: string;
  initialWish?: string;
  changeNote?: string;
  nonce: string;
  expiresAt: number;
}

/** 営業 AI エージェントが示す申込書（present_application の引数）。 */
export interface Application {
  customer: string;
  plan: Plan;
  offerSetId: string;
  intentSignature: string;
  nonce: string;
  expiresAt: number;
}

/** 確認画面の 1 行。 */
export interface Row {
  label: string;
  value: string;
  key: string;
}

const yen = (n: number) => `${n.toLocaleString("ja-JP")} 円`;

/**
 * D23: 意向確認書面の画面（署名の 1/2）は、意向確認の内容そのものから作る。営業 AI エージェントの説明文は使わない。
 * 案の名前は、意向確認の案の番号で、署名を確かめた提示（D22）から引く。
 */
export function intentRowsOf(intent: Intent, plans: Plan[]): Row[] {
  return [
    { key: "customer", label: "契約者", value: intent.customer },
    { key: "plan-name", label: "選んだ案", value: plans.find((p) => p.id === intent.planId)?.name ?? "（示された案にない）" },
    { key: "plan-id", label: "案の番号", value: intent.planId },
    // 振返り: 当初の意向と最終の意向を比べて読めるようにする（P-17）
    ...(intent.initialWish ? [{ key: "initial-wish", label: "当初の意向", value: intent.initialWish }] : []),
    { key: "wish", label: intent.initialWish ? "最終の意向" : "意向", value: intent.wish },
    ...(intent.changeNote ? [{ key: "change-note", label: "違いと経緯", value: intent.changeNote }] : []),
  ];
}

/** D23: 申込書の画面（署名の 2/2）は、申込みの内容そのものから作る。 */
export function applicationRowsOf(application: Application): Row[] {
  return [
    { key: "customer", label: "契約者", value: application.customer },
    { key: "plan-name", label: "申し込む案", value: application.plan.name },
    { key: "plan-id", label: "案の番号", value: application.plan.id },
    { key: "benefit", label: "年金の年額", value: yen(application.plan.benefit) },
    { key: "monthly", label: "月額の保険料", value: yen(application.plan.monthly) },
    { key: "intent-signed", label: "意向確認書面", value: "署名済み" },
  ];
}

/** 取決め（authorization_details）を、顧客が読める行にする。 */
export function termsRowsOf(terms: { kinds: string[]; maxBenefit: number }[]): Row[] {
  const kind: Record<string, string> = { fixed: "確定年金", lifetime: "終身年金" };
  return terms.flatMap((t) => [
    { key: "kinds", label: "申し込める保険", value: t.kinds.map((k) => kind[k] ?? k).join("、") },
    { key: "max-benefit", label: "年金の年額の上限", value: `${(t.maxBenefit / 10_000).toLocaleString("ja-JP")} 万円` },
  ]);
}

/** 回を始める前に A を更新する、残り時間の境目。営業 AI エージェントの 1 回の番が、途中で切れないだけの余裕を持つ。 */
export const REFRESH_MARGIN_MS = 120_000;

/** A の残りが短く、更新が要るか（P-18）。中身を読むだけで、確かめは、受け取る側の token-guard が行う。 */
export function needsRefresh(token: string, now: number, marginMs = REFRESH_MARGIN_MS): boolean {
  const { exp } = decodeJwt(token);
  return exp !== undefined && exp * 1000 - now < marginMs;
}
