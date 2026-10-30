// 保険会社の保険会社のシステムの記憶。教材なのでメモリ上に置く。
import { generateKeyPair, exportJWK, type JWK } from "jose";
import { urls, type Application, type Contract, type Notice, type Plan } from "@gekko/shared";

// 案の一覧。保険会社が出せる商品(無選択型の個人年金保険)。
export const catalog: Plan[] = [
  { id: "fixed-60", name: "確定年金 10年・年額60万円", kind: "fixed", benefit: 600_000, monthly: 20_000 },
  { id: "fixed-120", name: "確定年金 10年・年額120万円", kind: "fixed", benefit: 1_200_000, monthly: 40_000 },
  { id: "life-120", name: "終身年金・年額120万円", kind: "lifetime", benefit: 1_200_000, monthly: 60_000 },
  { id: "life-240", name: "終身年金・年額240万円", kind: "lifetime", benefit: 2_400_000, monthly: 120_000 },
];

// 顧客と、登録済みの連絡先(通知の宛先)。本人確認のときに届け出たものを想定する。
export const customers: Record<string, { contact: string }> = {
  alice: { contact: `${urls.customerApp}/notices?customer=alice` },
  bob: { contact: `${urls.customerApp}/notices?customer=bob` },
  mallory: { contact: `${urls.customerApp}/notices?customer=mallory` },
};

// 提示の署名鍵。保険会社の鍵で、トークンの発行元(認可サーバー)の鍵とは別にする。
const { publicKey, privateKey } = await generateKeyPair("ES256");
export const offerKid = "offer-key-1";
export const offerKey = { publicKey, privateKey };
export const offerJwk: JWK = { ...(await exportJWK(publicKey)), kid: offerKid, alg: "ES256", use: "sig" };

// 提示と一緒に出した nonce。申込みは一度しか受け付けない。
export const nonces = new Map<string, { customer: string; expiresAt: number; used: boolean }>();

// 契約の記録。揉めたときの証拠として、署名済みの申込みと提示、取り次いだ窓口も残す。
export interface ContractRecord {
  contract: Contract;
  by: string[];
  at: number;
  application: Application;
  intent: unknown;
  assertion: unknown;
  offerJws?: string;
}
export const contracts: ContractRecord[] = [];

// 保険会社が顧客へ直接送った通知。AI を通らない。
export const outbox: { to: string; notice: Notice; delivered: boolean }[] = [];

export function resetState() {
  contracts.length = 0;
  outbox.length = 0;
  nonces.clear();
}
