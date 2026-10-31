// 顧客のアプリ（段 1 は最小限。画面は段 2 で作る）。
// 保険会社のシステムが、登録済みの連絡先へ直接送る契約内容を受ける（P-8、P-14）。AI を通らない。
// 送り手は、Envoy が渡す相手の証明書の情報（XFCC）で、保険会社のシステムの SPIFFE ID に限る。
import { Hono } from "hono";

export interface Notice {
  customer: string;
  contract: Record<string, unknown>;
}

const backendId = () =>
  `spiffe://${process.env.TRUST_DOMAIN ?? "gekko11.internal"}/ns/${process.env.NAMESPACE ?? "secure"}/sa/insurer-backend`;

/** Envoy の XFCC（SANITIZE_SET）から、相手の SPIFFE ID を読む。 */
export function peerOf(xfcc: string | undefined): string | undefined {
  return xfcc
    ?.split(",")[0]
    ?.split(";")
    .find((part) => part.startsWith("URI="))
    ?.slice(4)
    .replace(/"/g, "");
}

export function createApp() {
  const app = new Hono();
  const notices: Notice[] = [];

  app.post("/notices", async (c) => {
    if (peerOf(c.req.header("x-forwarded-client-cert")) !== backendId()) {
      return c.json({ error: "保険会社のシステムからの通知ではない" }, 403);
    }
    notices.push((await c.req.json()) as Notice);
    return c.body(null, 204);
  });

  // 顧客の端末の中の受信箱に当たる。段 2 では、画面がここを読む
  app.get("/api/notices", (c) => {
    const who = c.req.query("customer");
    return c.json(who ? notices.filter((n) => n.customer === who) : notices);
  });

  return app;
}
