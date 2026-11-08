// 顧客のアプリの配信元（D-41）。画面と、その設定と、提示の公開鍵を渡す。トークンは BFF が持ち、画面には渡さない。
// 保険会社のシステムが、登録済みの連絡先へ直接送る契約内容を、受信箱の番号ごとに受ける（P-8、P-14、D-26）。AI を通らない。
// 送り手は、Envoy が渡す相手の証明書の情報（XFCC）で、保険会社のシステムの SPIFFE ID に限る。
import { readFileSync } from "node:fs";
import { Hono } from "hono";
import { addBff } from "./bff.ts";
import { currentDefenses } from "./defenses.ts";

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

/** 受信箱の番号は、端末が作る推測できない値（D-26）。認可サーバーが受け付ける形と同じに限る。 */
const INBOX = /^[A-Za-z0-9_-]{22,64}$/;

/** 画面に渡す設定。入口の名前は、マニフェストの生成で決まる（D-25）。 */
// トークンと、ログインサーバー、営業 AI エージェント、認可サーバーの宛先は、画面に渡さない（BFF が持つ。D-41）
const config = () => ({
  appOrigin: process.env.APP_ORIGIN,
  rpId: process.env.RP_ID,
  terms: [{ type: "insurance_application", kinds: ["fixed", "lifetime"], maxBenefit: 1_200_000 }],
});

/** 画面のファイル。まとめた app.js は、イメージのビルドで作る。 */
const file = (path: string) => {
  try {
    return readFileSync(new URL(path, import.meta.url), "utf8");
  } catch {
    return undefined;
  }
};

/** 提示の公開鍵を、保険会社のシステムから、出口（Envoy が SVID で mTLS をかける）を通して取る。 */
const OFFER_KEYS_URL = process.env.OFFER_KEYS_URL ?? "http://127.0.0.1:15104/offers-jwks.json";
let offerKeys: { at: number; body: unknown } | undefined;

/**
 * 画面の CSP（G32。P-18）。画面でコードを動かされたときの第 2 の守りで、XSS をなくすものではない。
 * 読み込むものを配信元のスクリプトとスタイルに限る。つなぐ先を、自分の配信元（BFF）に限る。
 */
export function contentSecurityPolicy(): string {
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    // 画面がつなぐのは、自分の配信元（BFF）だけ（D-41）
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

export function createApp() {
  const app = new Hono();
  const index = file("../dist/index.html");

  // BFF の受け口（D-41）。戻り先の /callback は、認可コードがあれば BFF が受け、なければ画面を返す
  addBff(app);
  for (const path of ["/", "/callback"]) app.get(path, (c) => (index ? c.html(index, 200, { "content-security-policy": contentSecurityPolicy() }) : c.notFound()));
  // まとめたスクリプトとスタイル。名前に内容のハッシュが入る
  app.get("/assets/:name{[A-Za-z0-9._-]+}", (c) => {
    const name = c.req.param("name");
    const body = file(`../dist/assets/${name}`);
    if (!body) return c.notFound();
    return c.body(body, 200, { "content-type": name.endsWith(".css") ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8" });
  });
  app.get("/config.json", (c) => c.json(config()));
  app.get("/offers-jwks.json", async (c) => {
    if (!offerKeys || Date.now() - offerKeys.at > 60_000) {
      const res = await fetch(OFFER_KEYS_URL).catch(() => undefined);
      if (!res?.ok) return c.json({ error: "提示の公開鍵を取れない" }, 502);
      offerKeys = { at: Date.now(), body: await res.json() };
    }
    return c.json(offerKeys.body as object);
  });
  // vulnerable だけ: 画面が、外した防御を読む（secure の版は持たない）
  app.get("/defenses", (c) => {
    const now = currentDefenses();
    return now ? c.json(now) : c.notFound();
  });
  // 受信箱の番号ごとの通知。番号は、顧客が passkey と一緒に登録した連絡先で、番号を持つ端末だけが読める
  const inboxes = new Map<string, Notice[]>();

  app.post("/notices/:inbox", async (c) => {
    if (peerOf(c.req.header("x-forwarded-client-cert")) !== backendId()) {
      return c.json({ error: "保険会社のシステムからの通知ではない" }, 403);
    }
    const inbox = c.req.param("inbox");
    if (!INBOX.test(inbox)) return c.json({ error: "受信箱の番号の形が違う" }, 400);
    inboxes.set(inbox, [...(inboxes.get(inbox) ?? []), (await c.req.json()) as Notice]);
    return c.body(null, 204);
  });

  // 顧客の端末の中の受信箱に当たる。画面は、自分の番号で読む
  app.get("/api/inbox/:inbox", (c) => c.json(inboxes.get(c.req.param("inbox")) ?? []));

  return app;
}
