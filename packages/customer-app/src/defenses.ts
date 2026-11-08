// 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
// 顧客のアプリの画面の防御（G22、G23）を、実行中に外す。ID トークンの確かめ（G21）は BFF が行い、外す受け口はない（D-41）。画面は、読み込みのときに、自分の origin の /defenses を読む。
// secure の版は、このファイルを defenses.secure.ts で置き換えてビルドし、切り替えの受け口を持たない（D-24）。
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const KNOWN = ["G22", "G23"];
const off = new Map<string, string>();

/** 画面に渡す、今の設定。 */
export const currentDefenses = (): { off: Record<string, string> } | undefined => ({ off: Object.fromEntries(off) });

/** 管理のポート。GET で今の設定を返し、PUT で置き換える（知らない ID は拒む）。 */
export function startAdmin(port: number): void {
  const app = new Hono();
  app.get("/defenses", (c) => c.json(currentDefenses()));
  app.put("/defenses", async (c) => {
    const next = Object.entries(((await c.req.json()) as { off?: Record<string, string> }).off ?? {});
    const unknown = next.filter(([id]) => !KNOWN.includes(id)).map(([id]) => id);
    if (unknown.length) return c.json({ error: `知らない防御: ${unknown.join(",")}` }, 400);
    off.clear();
    for (const [id, how] of next) off.set(id, how);
    return c.json(currentDefenses());
  });
  serve({ fetch: app.fetch, hostname: "0.0.0.0", port });
}
