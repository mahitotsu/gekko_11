// 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
// 防御を、実行中に 1 つずつ外せる。外した状態は、管理のポートで読み返せる。
// secure の版は、このファイルを defenses.secure.ts で置き換えてビルドし、切り替えの受け口を持たない（D-20）。
import { serve } from "@hono/node-server";
import { Hono } from "hono";

/** 外した防御と、その外し方（多くは "off"。D2 は "passthrough" か "client-credentials"）。 */
const off = new Map<string, string>();

export const enabled = (id: string): boolean => !off.has(id);
export const variant = (id: string): string | undefined => off.get(id);

/** 管理のポート。GET で今の設定を返し、PUT で置き換える（知らない ID は拒む）。 */
export function startAdmin(port: number, known: readonly string[]): void {
  const app = new Hono();
  const current = () => ({ off: Object.fromEntries(off) });
  app.get("/defenses", (c) => c.json(current()));
  app.put("/defenses", async (c) => {
    const body = (await c.req.json()) as { off?: Record<string, string> };
    const next = Object.entries(body.off ?? {});
    const unknown = next.filter(([id]) => !known.includes(id)).map(([id]) => id);
    if (unknown.length) return c.json({ error: `知らない防御: ${unknown.join(",")}` }, 400);
    off.clear();
    for (const [id, how] of next) off.set(id, how);
    return c.json(current());
  });
  serve({ fetch: app.fetch, hostname: "0.0.0.0", port });
}
