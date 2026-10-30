// 保険会社の認可サーバー(教材用の簡易版。本番では使わないこと)。
// 本人確認、トークンの発行(認可コード + PKCE + RAR)、トークンの替え(token exchange)、
// 営業 AI エージェントの登録と失効、トークンの有効性の問い合わせと失効、パスキーの登録を担当する。
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { createHash, randomUUID } from "node:crypto";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { jwtVerify } from "jose";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import {
  INTERNAL_KEY, ISSUER, audiences, modeOf, ports, urls, verifyTicketGood, VerifyError,
  type InsuranceTerms, type Ticket, type VerifiedClaims,
} from "@gekko/shared";
import { clients, codes, challenges, passkeys, revokedJti, sessions, users } from "./store.js";
import { issue, issueIdToken, jwk, publicKey } from "./issuer.js";
import { esc, page } from "./html.js";

const RP_ID = "localhost";
const RP_NAME = "教材保険会社";
// パスキーの登録は認可サーバーの画面で、署名は顧客のアプリの画面で行う。どちらの origin も許可する。
const ORIGINS = [urls.insurerAuth, urls.customerApp];
const ACR_PASSWORD = "urn:gekko:acr:password";

const app = new Hono();

app.get("/jwks.json", (c) => c.json({ keys: [jwk] }));

// ---- ログイン(本人確認) ----
app.get("/login", (c) => {
  const next = c.req.query("next") ?? "/passkeys";
  const options = Object.entries(users).map(([id, u]) => `<option value="${id}">${esc(u.name)}</option>`).join("");
  return c.html(page("保険会社: ログイン", `
    <p>ログインします。(教材なのでパスワードは常に <code>demo</code> です)</p>
    <form method="post" action="/login"><input type="hidden" name="next" value="${esc(next)}">
    <select name="user">${options}</select><br><input name="password" type="password" value="demo"><br>
    <button>ログインする</button></form>`));
});
const authTimes = new Map<string, number>(); // cookie -> ログインした時刻(epoch 秒)
app.post("/login", async (c) => {
  const f = await c.req.parseBody();
  if (typeof f.user !== "string" || !users[f.user] || f.password !== "demo") return c.text("ログインに失敗しました", 401);
  const sid = randomUUID();
  sessions.set(sid, f.user);
  authTimes.set(sid, Math.floor(Date.now() / 1000));
  setCookie(c, "rs", sid, { httpOnly: true, sameSite: "Lax", path: "/" });
  const next = typeof f.next === "string" && f.next.startsWith("/") ? f.next : "/passkeys";
  return c.redirect(next);
});
const sessionId = (c: Parameters<typeof getCookie>[0]) => getCookie(c, "rs") ?? "";
const sessionUser = (c: Parameters<typeof getCookie>[0]) => sessions.get(sessionId(c));

// ---- パスキーの登録 ----
// exports に載っていないバンドルは、本体の位置(script/index.js)から相対で辿る。
const browserJs = readFileSync(
  join(dirname(createRequire(import.meta.url).resolve("@simplewebauthn/browser")), "../dist/bundle/index.umd.min.js"), "utf8");
app.get("/webauthn-browser.js", (c) => c.body(browserJs, 200, { "content-type": "text/javascript" }));

app.get("/passkeys", (c) => {
  const user = sessionUser(c);
  if (!user) return c.redirect("/login?next=/passkeys");
  const n = passkeys.get(user)?.length ?? 0;
  return c.html(page("保険会社: パスキーの登録", `
    <p><b>${esc(users[user]!.name)}</b> さんのパスキーは現在 <b>${n}</b> 件です。</p>
    <p class="muted">パスキーは、意向確認と申込みの内容に署名する道具です。本人のものであることを確かめるため、保険会社へ登録しておきます。</p>
    <button id="reg">パスキーを登録する</button> <p id="msg"></p>
    <script src="/webauthn-browser.js"></script>
    <script>
    document.getElementById('reg').onclick = async () => {
      const m = document.getElementById('msg');
      try {
        const opt = await (await fetch('/passkeys/register/options', {method:'POST'})).json();
        const att = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: opt });
        const r = await fetch('/passkeys/register/verify', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(att)});
        m.textContent = r.ok ? '登録しました。' : '失敗: ' + await r.text();
        if (r.ok) setTimeout(() => location.reload(), 800);
      } catch (e) { m.textContent = '失敗: ' + e; }
    };
    </script>`));
});
app.post("/passkeys/register/options", async (c) => {
  const user = sessionUser(c);
  if (!user) return c.text("要ログイン", 401);
  const opts = await generateRegistrationOptions({
    rpName: RP_NAME, rpID: RP_ID, userName: user,
    userID: new TextEncoder().encode(user),
    attestationType: "none",
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  });
  challenges.set(user, opts.challenge);
  return c.json(opts);
});
app.post("/passkeys/register/verify", async (c) => {
  const user = sessionUser(c);
  const expectedChallenge = user && challenges.get(user);
  if (!user || !expectedChallenge) return c.text("要ログイン", 401);
  const v = await verifyRegistrationResponse({
    response: await c.req.json(), expectedChallenge, expectedOrigin: ORIGINS, expectedRPID: RP_ID,
    requireUserVerification: true,
  });
  if (!v.verified) return c.text("検証失敗", 400);
  const { id, publicKey, counter } = v.registrationInfo.credential;
  passkeys.set(user, [...(passkeys.get(user) ?? []), { id, publicKey, counter }]);
  challenges.delete(user);
  return c.json({ ok: true });
});
// 保険会社のシステムが、署名した人を確かめるためにパスキーの公開鍵を引く内部 API。
app.get("/internal/passkeys/:user", (c) => {
  if (c.req.header("x-internal-key") !== INTERNAL_KEY) return c.text("forbidden", 403);
  const list = (passkeys.get(c.req.param("user")) ?? []).map((p) => ({
    id: p.id, publicKey: Buffer.from(p.publicKey).toString("base64url"), counter: p.counter,
  }));
  return c.json(list);
});

// ---- 営業 AI エージェントの登録 (RFC 7591 の最小形)。登録を外すと、新しいトークンを出さず、出したトークンも無効になる ----
app.post("/register", async (c) => {
  if (c.req.header("x-internal-key") !== INTERNAL_KEY) return c.text("forbidden", 403);
  const b = (await c.req.json()) as { client_id: string; client_name: string };
  if (clients[b.client_id]) return c.json({ error: "invalid_client_metadata", error_description: "登録済みです" }, 400);
  const secret = randomUUID();
  clients[b.client_id] = { name: b.client_name, secret, redirectUris: [] };
  return c.json({ client_id: b.client_id, client_secret: secret }, 201);
});
app.post("/admin/clients/:id/revoke", (c) => {
  if (c.req.header("x-internal-key") !== INTERNAL_KEY) return c.text("forbidden", 403);
  const rec = clients[c.req.param("id")];
  if (!rec) return c.text("not found", 404);
  rec.revoked = true;
  return c.json({ client_id: c.req.param("id"), revoked: true });
});

// ---- トークンの発行(認可コードフロー + PKCE + RAR) ----
app.get("/authorize", (c) => {
  const q = c.req.query();
  const client = clients[q.client_id ?? ""];
  if (!client || !client.redirectUris.includes(q.redirect_uri ?? "")) return c.text("不正なクライアントです", 400);
  const user = sessionUser(c);
  if (!user) return c.redirect(`/login?next=${encodeURIComponent(new URL(c.req.url).pathname + new URL(c.req.url).search)}`);
  let terms: InsuranceTerms[];
  try { terms = JSON.parse(q.authorization_details ?? "[]"); } catch { return c.text("authorization_details が不正です", 400); }
  const t = terms[0];
  const hasKey = (passkeys.get(user)?.length ?? 0) > 0;
  return c.html(page("保険会社: 営業 AI エージェントへの許可", `
    <p><b>${esc(users[user]!.name)}</b> さん、営業 AI エージェントに、次の範囲で、案の提案と、あなたの代理での申込みを許可しますか？</p>
    <div class="card"><b>許可する範囲</b><br>
      ・扱える保険の種類は <b>${esc((t?.kinds ?? []).join(", ") || "なし")}</b><br>
      ・年金の年額は 1 件あたり <b>${t ? t.maxBenefit.toLocaleString() : 0} 円</b> まで</div>
    ${hasKey ? "" : `<p>⚠ パスキーがまだ未登録です。<a href="/passkeys" target="_blank">先に登録</a>してください。</p>`}
    <form method="post" action="/authorize/approve">
      ${["client_id", "redirect_uri", "state", "code_challenge"].map((k) => `<input type="hidden" name="${k}" value="${esc(q[k] ?? "")}">`).join("")}
      <input type="hidden" name="authorization_details" value="${esc(JSON.stringify(terms))}">
      <button>この範囲で許可する</button></form>`));
});
app.post("/authorize/approve", async (c) => {
  const user = sessionUser(c);
  if (!user) return c.text("要ログイン", 401);
  const f = (await c.req.parseBody()) as Record<string, string>;
  const client = clients[f.client_id ?? ""];
  if (!client || !client.redirectUris.includes(f.redirect_uri ?? "")) return c.text("不正なクライアントです", 400);
  const code = randomUUID();
  codes.set(code, {
    user, clientId: f.client_id!, redirectUri: f.redirect_uri!, codeChallenge: f.code_challenge!,
    terms: JSON.parse(f.authorization_details || "[]"), authTime: authTimes.get(sessionId(c)) ?? 0, expiresAt: Date.now() + 60_000,
  });
  const u = new URL(f.redirect_uri!);
  u.searchParams.set("code", code);
  if (f.state) u.searchParams.set("state", f.state);
  return c.redirect(u.toString());
});

// ---- /token: 営業 AI エージェント向けのトークン(authorization_code) / 替えたトークン(token-exchange) / 窓口自身のトークン(client_credentials) ----
// 窓口ごとに渡せる先。
const EXCHANGE = { "sales-agent": audiences.mcp, "insurer-mcp": audiences.backend } as const;
const OWN_AUD = { "sales-agent": audiences.sales, "insurer-mcp": audiences.mcp } as const;
type Exchanger = keyof typeof EXCHANGE;

function authClient(c: { req: { header: (n: string) => string | undefined } }, f: Record<string, string>) {
  let id = f.client_id, secret = f.client_secret;
  const basic = c.req.header("authorization")?.match(/^Basic (.+)$/);
  if (basic) [id, secret] = Buffer.from(basic[1]!, "base64").toString().split(":");
  const client = clients[id ?? ""];
  if (!client || !id || !client.secret || client.secret !== secret) return null; // 秘密を持たないクライアント(公開クライアント)は認証できない
  return id;
}

// 本人確認が済んだ属性。確認の記録がある顧客だけに付く。
function verifiedOf(user: string): VerifiedClaims | undefined {
  const u = users[user];
  if (!u?.verification) return undefined;
  return { verification: { trust_framework: "jp_aml", ...u.verification }, claims: { name: u.name } };
}

// 替えるときに取決めを狭める。良い発行は広げさせない。
function narrow(orig: InsuranceTerms[] | undefined, req: InsuranceTerms[] | undefined): InsuranceTerms[] | undefined {
  if (!req) return orig;
  if (modeOf("auth") === "bad") return req; // 悪い発行: 要求どおり(広げられる)
  const o = orig?.[0];
  const r = req[0];
  if (!o || !r) return orig;
  return [{ type: "insurance_application", kinds: r.kinds.filter((k) => o.kinds.includes(k)), maxBenefit: Math.min(o.maxBenefit, r.maxBenefit) }];
}

app.post("/token", async (c) => {
  const f = (await c.req.parseBody()) as Record<string, string>;
  const err = (e: string, d: string, s: 400 | 401 = 400) => c.json({ error: e, error_description: d }, s);

  if (f.grant_type === "authorization_code") {
    const rec = codes.get(f.code ?? "");
    codes.delete(f.code ?? "");
    if (!rec || rec.expiresAt < Date.now() || rec.clientId !== f.client_id || rec.redirectUri !== f.redirect_uri)
      return err("invalid_grant", "コードが不正です");
    const challenge = createHash("sha256").update(f.code_verifier ?? "").digest("base64url");
    if (challenge !== rec.codeChallenge) return err("invalid_grant", "PKCE が一致しません");
    const token = await issue({
      sub: rec.user, aud: audiences.sales, clientId: rec.clientId, scope: "consult apply", terms: rec.terms,
      acr: ACR_PASSWORD, authTime: rec.authTime, verified: verifiedOf(rec.user),
    });
    return c.json({ access_token: token, id_token: await issueIdToken(rec.user, rec.clientId), token_type: "Bearer", expires_in: 600 });
  }

  const client = authClient(c, f);
  if (!client || client === "customer-app") return err("invalid_client", "クライアント認証に失敗しました", 401);
  if (clients[client]!.revoked) return err("invalid_client", "登録が外れています", 401);

  if (f.grant_type === "urn:ietf:params:oauth:grant-type:token-exchange") {
    const target = EXCHANGE[client as Exchanger];
    if (!target || (f.audience && f.audience !== target)) return err("invalid_target", "この窓口から渡せない宛先です");
    let subject: Ticket;
    try { subject = await verifyTicketGood(f.subject_token ?? "", OWN_AUD[client as Exchanger]); }
    catch (e) { return err("invalid_grant", e instanceof VerifyError ? e.message : "subject_token が不正です"); }
    if (subject.jti && revokedJti.has(subject.jti)) return err("invalid_grant", "失効したトークンです");
    const terms = narrow(subject.authorization_details, f.authorization_details ? JSON.parse(f.authorization_details) : undefined);
    const token = await issue({
      sub: subject.sub, aud: target, clientId: client, scope: subject.scope ?? "", terms,
      act: { sub: client, ...(subject.act ? { act: subject.act } : {}) },
      acr: subject.acr, authTime: subject.auth_time, verified: subject.verified_claims,
    });
    return c.json({ access_token: token, issued_token_type: "urn:ietf:params:oauth:token-type:access_token", token_type: "Bearer", expires_in: 600 });
  }

  if (f.grant_type === "client_credentials") {
    // 窓口自身の資格でトークンをもらう。利用者(sub)は含まれない。悪い実装の再現に使う。
    const target = EXCHANGE[client as Exchanger];
    if (!target) return err("invalid_target", "宛先がありません");
    const token = await issue({ sub: client, aud: target, clientId: client, scope: "service" });
    return c.json({ access_token: token, token_type: "Bearer", expires_in: 600 });
  }
  return err("unsupported_grant_type", String(f.grant_type));
});

// ---- トークンの失効 (RFC 7009) と有効性の問い合わせ (RFC 7662) ----
async function parseOwn(token: string) {
  try {
    const { payload } = await jwtVerify(token, publicKey, { algorithms: ["ES256"], issuer: ISSUER });
    return payload as Ticket;
  } catch { return undefined; }
}
app.post("/revoke", async (c) => {
  const f = (await c.req.parseBody()) as Record<string, string>;
  if (!authClient(c, f)) return c.json({ error: "invalid_client" }, 401);
  const t = await parseOwn(f.token ?? "");
  if (t?.jti) revokedJti.add(t.jti);
  return c.body(null, 200); // トークンが不明でも 200 を返す(RFC 7009)
});
app.post("/introspect", async (c) => {
  const f = (await c.req.parseBody()) as Record<string, string>;
  const caller = authClient(c, f);
  if (!caller) return c.json({ error: "invalid_client" }, 401);
  const t = await parseOwn(f.token ?? "");
  if (!t) return c.json({ active: false });
  // 取り次いだ窓口(act の連鎖)と、トークンを取ったクライアントが、全て登録されていて有効か。
  const chain: string[] = [];
  for (let a = t.act; a; a = a.act) chain.push(a.sub);
  if (t.client_id) chain.push(t.client_id);
  const valid = chain.every((id) => clients[id] && !clients[id]!.revoked);
  const active = valid && !(t.jti && revokedJti.has(t.jti));
  return c.json(active ? { active, sub: t.sub, client_id: t.client_id, aud: t.aud, scope: t.scope, exp: t.exp, act: t.act } : { active: false });
});

serve({ fetch: app.fetch, port: ports.insurerAuth }, () =>
  console.log(`[insurer-auth] ${urls.insurerAuth} (発行モード: ${modeOf("auth")})`));
