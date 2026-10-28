// 顧客のアプリ(最小限)。画面は次の回で作る。
// 今は、各窓口が出すイベントの受け口と、保険会社が直接送る通知の受け口だけを持つ。
import { Hono } from "hono";
import type { InsurerEvent, Notice } from "@gekko/shared";

export function createApp() {
  const app = new Hono();
  const events: InsurerEvent[] = [];
  const notices: Notice[] = [];

  app.get("/", (c) => c.text("顧客のアプリ(画面は未実装です)。/api/events と /api/notices を参照できます。"));

  // 各窓口が何を受け取り、何を照合したか
  app.post("/events", async (c) => {
    events.push((await c.req.json()) as InsurerEvent);
    if (events.length > 200) events.shift();
    return c.body(null, 204);
  });
  app.get("/api/events", (c) => c.json(events));

  // 保険会社が、登録済みの連絡先へ直接送る通知(証券に当たる)。AI を通らない。
  app.post("/notices", async (c) => {
    notices.push((await c.req.json()) as Notice);
    return c.body(null, 204);
  });
  app.get("/api/notices", (c) => {
    const who = c.req.query("customer");
    return c.json(who ? notices.filter((n) => n.customer === who) : notices);
  });
  app.post("/api/reset", (c) => { events.length = 0; notices.length = 0; return c.body(null, 204); });
  return app;
}
