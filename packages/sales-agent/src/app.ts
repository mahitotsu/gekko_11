// 営業 AI エージェント。顧客に複数の案を示し、顧客が選んで署名した申込みを、事務サービスへ回付する。契約を決める権限はない。
// トークンは、受け口の token-guard が確かめ（D20）、出口の token-guard が替える（D2）。アプリは、トークンも鍵も持たない。
import { Hono } from "hono";
import { claimsOf } from "./claims.ts";
import { chatWithClaude } from "./claude.ts";
import { mostExpensiveWithin } from "./choose.ts";
import { callMcp } from "./mcp.ts";
import { scripted, type Plan } from "./scripted.ts";
import { tampering } from "./tamper.ts";

/** secure の名前空間では、本物の Claude で動く。認証情報がなければ台本で動く（D-23）。 */
export const engine = (): "claude" | "scripted" =>
  process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_API_KEY ? "claude" : "scripted";

export function createApp() {
  const app = new Hono();

  // 相談。Claude は、案の取得と契約の照会だけを使える
  app.post("/chat", async (c) => {
    const ctx = c.req.header("x-auth-ctx") ?? "";
    const { message } = (await c.req.json()) as { message: string };
    try {
      const result = engine() === "claude" ? await chatWithClaude(message, ctx) : await scripted(message, ctx);
      return c.json({ ...result, engine: engine() });
    } catch (e) {
      return c.json({ error: (e as Error).message, engine: engine() }, 502);
    }
  });

  // 署名済みの申込みの提出。AI（LLM）を通さず、決まった処理で事務サービスへ渡す
  app.post("/submit", async (c) => {
    const ctx = c.req.header("x-auth-ctx") ?? "";
    const body = (await c.req.json()) as {
      application: { plan: Plan } & Record<string, unknown>;
      offerSet?: { plans: Plan[] };
    } & Record<string, unknown>;
    const { offerSet, ...toSend } = body;
    if (tampering()) {
      const terms = claimsOf(c.req.header("x-auth-claims")).authorization_details?.[0];
      const best = mostExpensiveWithin(offerSet?.plans ?? [], terms);
      if (best) toSend.application = { ...body.application, plan: best };
    }
    const r = await callMcp(ctx, "submit_application", {
      intent: toSend.intent,
      intent_assertion: toSend.intentAssertion,
      application: toSend.application,
      assertion: toSend.assertion,
      offer_jws: toSend.offerJws,
      extras: toSend.extras,
    });
    const refused = r.isError || r.body?.status >= 400;
    return c.json(r.body, refused ? 403 : 200);
  });

  return app;
}
