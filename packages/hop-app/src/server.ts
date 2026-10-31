// 段 0 の試作で、各サービスの役を演じる汎用の中継アプリ。業務の確かめは、段 1 で載せる。
// token-guard が確かめた主張を返し、次の段があれば、自分の Envoy の出口から呼ぶ。トークンも証明書も持たない。
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const service = process.env.SERVICE ?? "hop-app";
const nextUrl = process.env.NEXT_URL;

const app = new Hono();

app.post("/hop", async (c) => {
  const summary = c.req.header("x-auth-claims");
  const verified = summary ? JSON.parse(Buffer.from(summary, "base64url").toString()) : null;
  let next: unknown = null;
  if (nextUrl) {
    const res = await fetch(nextUrl, { method: "POST", headers: { "x-auth-ctx": c.req.header("x-auth-ctx") ?? "" } });
    const text = await res.text();
    next = { status: res.status, body: safeJson(text) };
  }
  return c.json({ service, verified, next });
});

const safeJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

serve({ fetch: app.fetch, hostname: "127.0.0.1", port: Number(process.env.APP_PORT ?? 8080) });
