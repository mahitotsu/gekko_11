// Claude を使わないときの台本（vulnerable の名前空間と、認証情報のない環境）。同じ道具を、決まった順で呼ぶ。
import { callMcp } from "./mcp.ts";

export interface ChatResult {
  reply: string;
  offer?: unknown;
  tools: string[];
}

export interface Plan {
  id: string;
  name: string;
  kind: string;
  benefit: number;
  monthly: number;
}

export async function scripted(message: string, ctx: string): Promise<ChatResult> {
  if (/契約|一覧|照会/.test(message)) {
    const r = await callMcp(ctx, "list_contracts");
    return {
      reply: r.isError ? `契約を調べられませんでした: ${JSON.stringify(r.body)}` : `契約は ${r.body.contracts.length} 件です。`,
      tools: ["list_contracts"],
    };
  }
  const r = await callMcp(ctx, "get_offers");
  if (r.isError || r.body.error) return { reply: `案を取得できませんでした: ${JSON.stringify(r.body)}`, tools: ["get_offers"] };
  const plans = r.body.offerSet.plans as Plan[];
  const lines = plans.map((p) => `${p.name}(月額 ${p.monthly.toLocaleString()} 円)`).join("、");
  return {
    reply: `複数の案を用意しました: ${lines}。案を比べて、ご自身のアプリで選んで署名してください。`,
    offer: r.body,
    tools: ["get_offers"],
  };
}
