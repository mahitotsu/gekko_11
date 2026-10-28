// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
// 事務センターを呼ぶための票を用意する。
import { actChain, audiences, urls, type Ticket } from "@gekko/shared";
import { config } from "./config.js";

const cache = new Map<string, { token: string; exp: number }>();
const basic = "Basic " + Buffer.from("insurer-mcp:insurer-mcp-secret").toString("base64");

async function post(form: Record<string, string>): Promise<string> {
  const res = await fetch(`${urls.insurerAuth}/token`, {
    method: "POST", headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form),
  });
  const j = (await res.json()) as { access_token?: string; error_description?: string };
  if (!j.access_token) throw new Error(`認可サーバーが票を出しませんでした: ${j.error_description}`);
  return j.access_token;
}

export interface BackendTicket { token: string; how: string }

export async function ticketForBackend(incoming: string, ticket: Ticket): Promise<BackendTicket> {
  switch (config.backendAuth) {
    case "passthrough":
      return { token: incoming, how: "受け取った票をそのまま流用" };
    case "client-credentials": {
      const token = await post({ grant_type: "client_credentials" });
      return { token, how: "MCP 自身の票(利用者は含まれない)" };
    }
    case "exchange": {
      const hit = cache.get(incoming);
      if (hit && hit.exp > Date.now() / 1000 + 30) return { token: hit.token, how: "替えた票(token exchange・キャッシュ)" };
      const token = await post({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: incoming, subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        audience: audiences.backend,
      });
      cache.set(incoming, { token, exp: ticket.exp ?? 0 });
      return { token, how: `替えた票(token exchange)。経由: ${actChain(ticket.act).join(" → ") || "なし"} → insurer-mcp` };
    }
  }
}
