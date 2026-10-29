import { modeOf } from "@gekko/shared";

// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
// 保険会社のシステムを呼ぶとき、どのトークンを使うか。
export type BackendAuth =
  | "exchange" // 良い: 受け取ったトークンを認可サーバーに出し、保険会社のシステム宛てのトークンに替えてもらう(利用者本人が残る)
  | "passthrough" // 悪い: 受け取ったトークンをそのまま保険会社のシステムへ流す(宛先が違うトークンを使い回す)
  | "client-credentials"; // 悪い: 事務サービス自身のトークンで呼び、本人は引数の on_behalf_of を信じさせる

export type IncomingCheck = "good" | "no-aud"; // 受け取ったトークンの宛先を見るか

export interface McpConfig { backendAuth: BackendAuth; incoming: IncomingCheck }
const bad = modeOf("mcp") === "bad";
export const config: McpConfig = {
  backendAuth: (process.env.MCP_BACKEND_AUTH as BackendAuth) ?? (bad ? "client-credentials" : "exchange"),
  incoming: (process.env.MCP_INCOMING_CHECK as IncomingCheck) ?? (bad ? "no-aud" : "good"),
};
export function setConfig(c: Partial<McpConfig>) { Object.assign(config, c); }
