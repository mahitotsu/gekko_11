// 保険会社の保険会社のシステムの記憶。教材なのでメモリ上に置く。
import { generateKeyPair, exportJWK, type JWK } from "jose";
import { urls, type Application, type Contract, type Notice, type Plan } from "@gekko/shared";

// 案の一覧。保険会社が出せる商品。
export const catalog: Plan[] = [
  { id: "med-light", name: "医療 ライト", kind: "medical", benefit: 50_000, monthly: 1_200 },
  { id: "med-plus", name: "医療 プラス", kind: "medical", benefit: 100_000, monthly: 2_400 },
  { id: "life-1000", name: "死亡 1,000万円", kind: "death", benefit: 10_000_000, monthly: 3_800 },
  { id: "life-3000", name: "死亡 3,000万円", kind: "death", benefit: 30_000_000, monthly: 9_500 },
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
