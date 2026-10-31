// token-guard。各 Pod で、Envoy の ext_authz として、受け口でトークンを確かめ、出口でトークンを替える（D-16）。
// アプリは、トークンも証明書も持たない。受け口で確かめた主張と、出口で使う控えの番号（x-auth-ctx）だけを受け取る。
import { randomUUID } from "node:crypto";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { config } from "./config.ts";
import { exchangeForNext } from "./exchange.ts";
import { checkIngress, Refusal } from "./verify.ts";

/** 受け口で確かめたトークンの控え。出口で、次の段のトークンに替えるために使う。 */
const held = new Map<string, { token: string; exp: number }>();

function hold(token: string, exp: number): string {
  const now = Date.now() / 1000;
  for (const [k, v] of held) if (v.exp < now) held.delete(k);
  const handle = randomUUID();
  held.set(handle, { token, exp });
  return handle;
}

const refuse = (e: unknown) => {
  if (e instanceof Refusal) return { status: e.status, error: e.message };
  return { status: 403 as const, error: `確かめに失敗した: ${(e as Error).message}` };
};

const app = new Hono();

app.all("/ingress/*", async (c) => {
  const path = c.req.path.slice("/ingress".length);
  try {
    const { token, claims, peer } = await checkIngress({
      method: c.req.method,
      url: `https://${c.req.header("host")}${path}`,
      authorization: c.req.header("authorization"),
      dpop: c.req.header("dpop"),
      xfcc: c.req.header("x-forwarded-client-cert"),
    });
    const summary = Buffer.from(JSON.stringify({ claims, peer })).toString("base64url");
    c.header("x-auth-sub", String(claims.sub));
    c.header("x-auth-claims", summary);
    c.header("x-auth-ctx", hold(token, claims.exp!));
    return c.body(null, 200);
  } catch (e) {
    const r = refuse(e);
    console.log(JSON.stringify({ at: "ingress", path, refused: r.error }));
    return c.json({ error: r.error }, r.status);
  }
});

app.all("/egress/*", async (c) => {
  const entry = held.get(c.req.header("x-auth-ctx") ?? "");
  if (!entry) return c.json({ error: "受け口で確かめたトークンの控えがない" }, 403);
  try {
    c.header("authorization", `Bearer ${await exchangeForNext(entry.token)}`);
    return c.body(null, 200);
  } catch (e) {
    const r = refuse(e);
    console.log(JSON.stringify({ at: "egress", refused: r.error }));
    return c.json({ error: r.error }, r.status);
  }
});

serve({ fetch: app.fetch, hostname: "127.0.0.1", port: config.port });
console.log(JSON.stringify({ service: config.service, ingress: config.ingress, next: config.next ?? null }));
