// 営業 AI エージェント。顧客と AG-UI でやりとりし（D-29）、意向を聞いて案を示し、書類に署名してもらい、顧客の代理として提出する。
// 契約を決める権限はない。トークンは、受け口の token-guard が確かめ（G20）、出口の token-guard が替える（G2）。
// アプリは、トークンも鍵も持たない。
import { Hono } from "hono";
import { handleRun } from "./agui.ts";
import { runClaude } from "./claude.ts";
import { scriptedTurn } from "./scripted.ts";
import type { Thread } from "./thread.ts";

/** secure の名前空間では、本物の Claude で動く。認証情報がなければ台本で動く（D-23）。 */
export const engine = (): "claude" | "scripted" =>
  process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_API_KEY ? "claude" : "scripted";

/** 会話を始める。Claude か台本が、顧客の文を待ち、番ごとに回を閉じる。 */
export function start(t: Thread): void {
  if (engine() === "claude") {
    void runClaude(t);
    return;
  }
  void (async () => {
    for await (const message of t.messages()) {
      try {
        await scriptedTurn(t, message);
        t.end();
      } catch (e) {
        t.end(`営業 AI エージェント（台本）が止まりました: ${(e as Error).message}`);
      }
    }
  })();
}

export function createApp() {
  const app = new Hono();
  app.post("/agui", (c) => handleRun(c, start));
  return app;
}
