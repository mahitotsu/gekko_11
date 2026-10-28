// 各サービスのポートと URL、動作モード。
import { existsSync } from "node:fs";

// リポジトリ直下の .env(CLAUDE_CODE_OAUTH_TOKEN など)があれば読み込む。
if (existsSync(".env")) process.loadEnvFile(".env");
const env = (k: string, d: string) => process.env[k] ?? d;

export const ports = {
  customerApp: Number(env("CUSTOMER_APP_PORT", "4000")),
  insurerAuth: Number(env("INSURER_AUTH_PORT", "4001")),
  salesAgent: Number(env("SALES_AGENT_PORT", "4002")),
  insurerMcp: Number(env("INSURER_MCP_PORT", "4003")),
  insurerBackend: Number(env("INSURER_BACKEND_PORT", "4004")),
};

export const urls = {
  customerApp: `http://localhost:${ports.customerApp}`,
  insurerAuth: `http://localhost:${ports.insurerAuth}`,
  salesAgent: `http://localhost:${ports.salesAgent}`,
  insurerMcp: `http://localhost:${ports.insurerMcp}`,
  insurerBackend: `http://localhost:${ports.insurerBackend}`,
};

// 票の発行元(iss)。
export const ISSUER = "insurer-auth";

// 票の宛先(aud)。窓口ごとに別の値にする。
export const audiences = {
  sales: "sales-agent",
  mcp: "insurer-mcp",
  backend: "insurer-backend",
} as const;

// サービス間の内部 API(パスキーの公開鍵の問い合わせなど)の合言葉。教材用の固定値。
export const INTERNAL_KEY = "dev-internal-key";

export type Mode = "good" | "bad";
// 例: INSURER_MODE=bad, INSURER_MODE_BACKEND=good のようにサービス単位で上書きできる。
export function modeOf(service: string): Mode {
  const v = process.env[`INSURER_MODE_${service.toUpperCase()}`] ?? process.env.INSURER_MODE ?? "good";
  return v === "bad" ? "bad" : "good";
}
