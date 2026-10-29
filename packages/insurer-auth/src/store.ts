// 保険会社の認可サーバーの記憶。教材なので全てメモリ上に置く。
import type { AuthenticatorTransport } from "@simplewebauthn/server";
import type { InsuranceTerms } from "@gekko/shared";

export interface UserRec {
  name: string;
  // 取引時確認(本人確認)の記録。無い顧客は、本人確認が済んでいない。
  verification?: { method: string; time: string };
}
export const users: Record<string, UserRec> = {
  alice: { name: "Alice(契約者)", verification: { method: "対面で本人確認書類を確認", time: "2026-01-15" } },
  bob: { name: "Bob(被保険者になる家族)", verification: { method: "対面で本人確認書類を確認", time: "2026-01-15" } },
  mallory: { name: "Mallory(本人確認が済んでいない顧客)" },
};

// クライアント。customer-app は公開クライアント(PKCE)、他は秘密を持つ。登録を外す(revoked)と、新しいトークンを出さない。
export interface ClientRec { secret?: string; redirectUris: string[]; name: string; revoked?: boolean }
const initialClients = (): Record<string, ClientRec> => ({
  "customer-app": { name: "顧客のアプリ", redirectUris: ["http://localhost:4000/callback"] },
  "sales-agent": { name: "営業 AI エージェント", secret: "sales-agent-secret", redirectUris: [] },
  "insurer-mcp": { name: "事務サービス", secret: "insurer-mcp-secret", redirectUris: [] },
  "insurer-backend": { name: "保険会社のシステム", secret: "insurer-backend-secret", redirectUris: [] },
});
export const clients: Record<string, ClientRec> = initialClients();

export interface Passkey {
  id: string;
  publicKey: Uint8Array;
  counter: number;
  transports?: AuthenticatorTransport[];
}
export const passkeys = new Map<string, Passkey[]>(); // user -> パスキー
export const sessions = new Map<string, string>(); // cookie -> user
export const challenges = new Map<string, string>(); // user -> 登録中の challenge
export const revokedJti = new Set<string>(); // 失効させたトークン

export interface AuthCode {
  user: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  terms: InsuranceTerms[];
  authTime: number;
  expiresAt: number;
}
export const codes = new Map<string, AuthCode>();

// テスト用: 登録と失効を初期状態に戻す。
export function resetAuthState() {
  for (const k of Object.keys(clients)) delete clients[k];
  Object.assign(clients, initialClients());
  revokedJti.clear();
}
