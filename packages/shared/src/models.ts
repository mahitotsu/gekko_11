// 保険の募集で扱う書類のモデル。申込みの内容は、API のパラメータに当たる。
export type PlanKind = "fixed" | "lifetime"; // 確定年金、終身年金

// 案。営業 AI エージェントが顧客に示す、個人年金保険の内容。契約者が被保険者で、年金を自分で受け取る。
export interface Plan {
  id: string;
  name: string;
  kind: PlanKind;
  benefit: number; // 年金の年額(円)
  monthly: number; // 月額の保険料(円)
}

// 取決め(RAR)。営業 AI エージェントが扱える保険の種類と、年金の年額の上限。
export interface InsuranceTerms {
  type: "insurance_application";
  kinds: PlanKind[];
  maxBenefit: number;
}

// 提示。保険会社が顧客ごとに出す、案の一式。
export interface OfferSet {
  customer: string;
  plans: Plan[];
}

// 意向確認。顧客が、案の一式から選んだ案と、その意向に署名する。
export interface Intent {
  customer: string;
  offerSetId: string;
  planId: string;
  wish: string; // 顧客の意向(例: 老後の生活費に備えたい)
  nonce: string;
  expiresAt: number; // epoch 秒
}

// 申込み。意向確認の署名の値を含めて、署名の連鎖を作る。
export interface Application {
  customer: string; // 契約者(被保険者と年金の受取人を兼ねる)
  plan: Plan;
  offerSetId: string;
  intentSignature: string; // 意向確認の署名の値
  nonce: string;
  expiresAt: number;
}

// 契約の記録。署名済みの申込みから、決定論的に導出する。
export interface Contract {
  contractId: string;
  customer: string;
  plan: Plan;
  offerSetId: string;
  nonce: string;
}

// 保険会社が顧客の登録済みの連絡先へ直接送る通知(証券に当たる)。
export interface Notice {
  customer: string;
  contract: Contract;
}

// 顧客の手元に残る、署名した申込みの写し。
export interface MyCopy {
  application: Application;
}
