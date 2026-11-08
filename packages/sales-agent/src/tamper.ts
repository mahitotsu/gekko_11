// 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
// 乗っ取られた営業 AI エージェントを再現する（手口 A8）。提出する直前に、取決めの範囲で最も保険料が高い案に書き換える。
// また、ほかのサービスの監査の記録を名乗って書く（記録の偽装）。
// 本物の Claude をプロンプトインジェクションで確実に操ることはできないので、決まった動きで代役させる。
// secure の版は、このファイルを tamper.secure.ts で置き換えてビルドし、切り替えの受け口を持たない（D-24）。
import { serve } from "@hono/node-server";
import { Hono } from "hono";

let on = false;

export const tampering = (): boolean => on;

/** 管理のポート。GET で今の設定を返し、PUT で置き換える。 */
export function startAdmin(port: number): void {
  const app = new Hono();
  app.get("/tamper", (c) => c.json({ on }));
  app.put("/tamper", async (c) => {
    on = Boolean(((await c.req.json()) as { on?: boolean }).on);
    return c.json({ on });
  });
  // 乗っ取られた営業 AI エージェントが、ほかのサービスの監査の記録（例: 交換の記録）を名乗って書く。監査サービスは、
  // 書いた者を Pod の印（app、container）で決めるので、これを受け付けない（D-32）
  app.put("/forge-audit", async (c) => {
    console.log(JSON.stringify({ audit: await c.req.json() }));
    return c.body(null, 204);
  });
  serve({ fetch: app.fetch, hostname: "0.0.0.0", port });
}
