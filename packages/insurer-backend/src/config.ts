import { modeOf } from "@gekko/shared";

// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
// 保険会社のシステムの検証の仕方。悪い側は、何を省くと何が起きるかを見せるための実装。
// 環境変数で選ぶ。INSURER_MODE_BACKEND=bad にすると、全項目が悪い側になる。

// トークンの検証(宛先、期限、署名、種類)
export type TicketCheck =
  | "good" // 署名・iss・aud・期限・typ を全て見る
  | "no-aud" // 宛先を見ない(別の窓口宛てのトークンが通る)
  | "no-exp" // 期限を見ない
  | "no-typ" // typ を見ない(別の用途のトークンが通る)
  | "no-signature" // 署名を見ない(alg=none や偽造が通る)
  | "signature-only"; // 署名だけ見る(悪い実装の標準)

// 申込みの内容がサイン時のままかの確かめ方
export type SealCheck =
  | "passkey" // 顧客のパスキーの署名と、内容のハッシュを照合する
  | "none" // 何も見ない
  | "mtls-only" // 通信相手が信頼できる窓口なら中身を信じる
  | "agent-signed"; // 営業 AI エージェント自身の署名で足りるとする

export interface BackendConfig {
  ticket: TicketCheck;
  seal: SealCheck;
  trustFromUser: boolean; // ツール引数の for_user を信じる(本人が消える実装)
  offers: "verify" | "none"; // 案が、保険会社の署名つきの提示に含まれるか
  chain: "verify" | "none"; // 意向確認と申込みの署名の連鎖
  range: "rar" | "none"; // 取決め(scope、扱える保険の種類、年金の年額の上限)との照合
  registration: "introspect" | "none"; // トークンを取り次いだ営業 AI エージェントの登録の有効性
  nonce: "once" | "none"; // 申込みは一度だけ
  identity: "token" | "agent-claim"; // 本人確認の済んだ属性を、トークンから取るか、営業 AI エージェントの申告から取るか
  ingest: "derive" | "manual"; // 契約の記録を、署名済み申込から導出するか、人が入力するか
  notify: "registered" | "from-application"; // 通知先を、登録済みの連絡先にするか、申込みに書かれた連絡先にするか
}

const bad = modeOf("backend") === "bad";
const pick = <T extends string>(name: string, good: T, badValue: T): T =>
  (process.env[`BACKEND_${name}`] as T | undefined) ?? (bad ? badValue : good);

export const config: BackendConfig = {
  ticket: pick<TicketCheck>("TICKET_CHECK", "good", "signature-only"),
  seal: pick<SealCheck>("SEAL_CHECK", "passkey", "none"),
  trustFromUser: process.env.BACKEND_TRUST_FROM_USER ? process.env.BACKEND_TRUST_FROM_USER === "1" : bad,
  offers: pick("OFFERS_CHECK", "verify", "none"),
  chain: pick("CHAIN_CHECK", "verify", "none"),
  range: pick("RANGE_CHECK", "rar", "none"),
  registration: pick("REGISTRATION_CHECK", "introspect", "none"),
  nonce: pick("NONCE_CHECK", "once", "none"),
  identity: pick("IDENTITY_SOURCE", "token", "agent-claim"),
  ingest: pick("INGEST", "derive", "manual"),
  notify: pick("NOTIFY", "registered", "from-application"),
};
const defaults = { ...config };
export function setConfig(c: Partial<BackendConfig>) {
  Object.assign(config, c);
}
export function resetConfig() {
  Object.assign(config, defaults);
}
const GOOD: BackendConfig = {
  ticket: "good", seal: "passkey", trustFromUser: false, offers: "verify", chain: "verify", range: "rar",
  registration: "introspect", nonce: "once", identity: "token", ingest: "derive", notify: "registered",
};
export const isGood = () => (Object.keys(GOOD) as (keyof BackendConfig)[]).every((k) => config[k] === GOOD[k]);
