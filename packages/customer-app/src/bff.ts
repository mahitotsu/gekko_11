// 顧客のアプリの BFF（D-41、RFC 10017 の 6.1 節）。OAuth の機密クライアントとして、ログインサーバーで A と P を受け取り、
// 画面の代わりに営業 AI エージェントと認可サーバーを呼ぶ。トークンと DPoP の鍵は、このサーバーのメモリにだけ置き、画面には出さない。
// 画面とは、HttpOnly の Cookie のセッションでつなぐ。顧客の承認（passkey の署名）は、今までどおり画面の端末で行う。
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { Readable } from "node:stream";
import type { Context, Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { compactVerify, createRemoteJWKSet, SignJWT } from "jose";
import * as oidc from "openid-client";
import { needsRefresh, verifyIdToken } from "../web/checks.ts";

const env = (name: string, fallback?: string) => process.env[name] ?? fallback ?? "";

/** BFF の設定。宛先は、決まった出口だけ（RFC 10017 の 6.1.3.6 節）。 */
const cfg = () => ({
  issuer: env("ISSUER"),
  appOrigin: env("APP_ORIGIN"),
  clientId: "customer-app",
  terms: [{ type: "insurance_application", kinds: ["fixed", "lifetime"], maxBenefit: 1_200_000 }],
  /** ログインサーバーへの出口。Envoy が、公開名の Host を付けて、相手の SPIFFE ID を確かめて送る。 */
  loginUrl: env("LOGIN_URL", "http://127.0.0.1:15105"),
  /** 営業 AI エージェントへの出口と、DPoP の htu に使う内部の名前。 */
  agentUrl: env("AGENT_URL", "http://127.0.0.1:15106"),
  agentOrigin: env("AGENT_ORIGIN_INTERNAL"),
  /** 認可サーバー（passkey の登録）への出口と、DPoP の htu に使う内部の名前。 */
  authUrl: env("AUTH_URL", "http://127.0.0.1:15101"),
  authOrigin: env("AUTH_ORIGIN_INTERNAL"),
  jwtSvidFile: env("JWT_SVID_FILE", "/svid/jwt_svid.token"),
});

/** セッションの Cookie。Secure、HttpOnly、SameSite=Strict、__Host-Http- の接頭辞（RFC 10017 の 6.1.3.2 節）。 */
const SESSION = "__Host-Http-session";
const LOGIN = "__Host-Http-login";
const COOKIE = { path: "/", secure: true, httpOnly: true, sameSite: "Strict" } as const;
/** ログインの上限（P-18）と、無操作で捨てるまでの時間。ログインサーバーの設定と揃える。 */
const MAX_AGE_MS = 60 * 60_000;
const IDLE_MS = 30 * 60_000;

interface Session {
  sub: string;
  idToken: string;
  /** DPoP の鍵。取り出せない鍵として作り、このサーバーのメモリにだけ置く。 */
  keys: CryptoKeyPair;
  dpop: oidc.DPoPHandle;
  access: string;
  refresh?: string;
  /** 受信箱の番号を、認可サーバーに登録できたか（D-26）。P は登録にだけ使い、持ち続けない（D-37）。 */
  inboxRegistered: boolean;
  /** passkey の作成か削除を頼んだときの結果（ログインサーバーの kc_action_status。D-42、D-43）。 */
  passkeyAction?: PasskeyAction;
  /** ログインサーバーにある、本人の passkey の一覧（D-43）。読めなかったときは undefined。 */
  passkeys?: Passkeys;
  created: number;
  used: number;
  renewing?: Promise<void>;
}

interface LoginState {
  kind: "apply" | "passkeys";
  verifier: string;
  state: string;
  nonce: string;
  /** P を受け取るときは、ログイン中のセッションに足す。 */
  sid?: string;
  /** 端末の受信箱の番号。P を受け取ったら、認可サーバーに登録する（D-26）。 */
  inbox?: string;
  /** この端末で、ログインと申込みの署名に使う passkey を登録してもらう（D-42）。 */
  register?: boolean;
  /** 本人の passkey を消してもらう。値は、ログインサーバーの中の資格情報の ID（D-43）。 */
  remove?: string;
  at: number;
}

/** 受信箱の番号は、端末が作る推測できない値（D-26）。 */
const INBOX = /^[A-Za-z0-9_-]{22,64}$/;

type PasskeyResult = "success" | "cancelled" | "error";
/** 本人の passkey の一覧。userHandle は passkey の利用者の ID（base64url）。公開鍵は含まない（D-43）。 */
export interface Passkeys {
  userHandle: string;
  passkeys: { id: string; ref: string; label: string; created: number; transports?: string[] }[];
}
/** ログインサーバーが戻り先に付ける、登録の結果。値がないか分からなければ、失敗とみなす。 */
export const passkeyResult = (status: string | null): PasskeyResult => (status === "success" || status === "cancelled" ? status : "error");
/** 頼んだ操作（作成か削除）と、その結果。 */
export interface PasskeyAction {
  action: "create" | "delete";
  status: PasskeyResult;
}
/** ログインサーバーの中の資格情報の ID（UUID）。ほかの形は、ログインサーバーに渡さない。 */
const CREDENTIAL_REF = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const sessions = new Map<string, Session>();
const logins = new Map<string, LoginState>();

/** A を更新できない。画面は、ログインし直しへ案内する。 */
class LoginExpired extends Error {}

/** 出口へ送る fetch。宛先の URL の Host を、そのまま付ける（Envoy の出口が、公開名に替える場合もある）。 */
export function egressFetch(base: string): typeof fetch {
  return (async (input: string | URL | Request, init: RequestInit = {}) => {
    const target = new URL(input instanceof Request ? input.url : String(input));
    const local = new URL(base);
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    const body = init.body === undefined || init.body === null ? undefined : init.body instanceof URLSearchParams ? init.body.toString() : String(init.body);
    return new Promise<Response>((resolve, reject) => {
      const req = request(
        { host: local.hostname, port: local.port, method: init.method ?? "GET", path: target.pathname + target.search, headers: { ...Object.fromEntries(headers), host: target.host } },
        (res) => {
          const out = new Headers();
          for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) out.set(k, Array.isArray(v) ? v.join(", ") : v);
          const status = res.statusCode ?? 502;
          resolve(new Response(status === 204 || status === 304 ? null : (Readable.toWeb(res) as ReadableStream), { status, headers: out }));
        },
      );
      req.on("error", reject);
      if (init.signal) init.signal.addEventListener("abort", () => req.destroy(new Error("aborted")));
      req.end(body);
    });
  }) as typeof fetch;
}

/** ログインサーバーの機密クライアントの設定。クライアント認証は、SPIRE の JWT-SVID（D-38、D-41）。 */
function client() {
  const c = cfg();
  const base = `${c.issuer}/protocol/openid-connect`;
  const config = new oidc.Configuration(
    { issuer: c.issuer, authorization_endpoint: `${base}/auth`, token_endpoint: `${base}/token`, jwks_uri: `${base}/certs` },
    c.clientId,
    {},
    (_as, _client, body) => {
      body.set("client_id", c.clientId);
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe");
      body.set("client_assertion", readFileSync(c.jwtSvidFile, "utf8").trim());
    },
  );
  oidc.allowInsecureRequests(config); // 教材の入口は TLS なし（implementation の 5 章）
  config[oidc.customFetch] = (url, options) => egressFetch(c.loginUrl)(url, options as RequestInit);
  return config;
}

/** ID トークンを確かめる（D21）。openid-client は既定で署名を確かめないので、自分で確かめる（D-40）。 */
async function checkIdToken(idToken: string, nonce: string) {
  const c = cfg();
  // 公開鍵は、ログインサーバーへの出口から取る（Envoy が、相手の SPIFFE ID を確かめる）
  const jwks = createRemoteJWKSet(new URL(`${c.loginUrl}/realms/insurer/protocol/openid-connect/certs`));
  return verifyIdToken(idToken, jwks, { issuer: c.issuer, clientId: c.clientId, nonce });
}

/** ログインサーバーのログアウトの URL。確かめられる ID トークンだけを示す（D-33）。示さなければ、ログインサーバーが確認の画面を出す。 */
export async function logoutUrl(idToken: string | undefined, jwks: Parameters<typeof compactVerify>[1]): Promise<string> {
  const { issuer, clientId, appOrigin } = cfg();
  const q = new URLSearchParams({ client_id: clientId, post_logout_redirect_uri: `${appOrigin}/` });
  if (idToken && (await compactVerify(idToken, jwks).catch(() => undefined))) q.set("id_token_hint", idToken);
  return `${issuer}/protocol/openid-connect/logout?${q}`;
}

/** DPoP の proof（RFC 9449）。BFF の鍵で、営業 AI エージェントと認可サーバーへの要求ごとに作る。 */
async function proof(session: Session, htm: string, htu: string, token: string) {
  const jwk = (await crypto.subtle.exportKey("jwk", session.keys.publicKey)) as Record<string, string>;
  const ath = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))).toString("base64url");
  return new SignJWT({ htm, htu, jti: crypto.randomUUID(), ath })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! } })
    .setIssuedAt()
    .sign(session.keys.privateKey);
}

const random = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");

/** 古いセッションとログインの途中を捨てる。 */
function sweep() {
  const now = Date.now();
  for (const [k, s] of sessions) if (now - s.created > MAX_AGE_MS || now - s.used > IDLE_MS) sessions.delete(k);
  for (const [k, l] of logins) if (now - l.at > 10 * 60_000) logins.delete(k);
}

function current(c: Context): Session | undefined {
  sweep();
  const sid = getCookie(c, SESSION);
  const session = sid ? sessions.get(sid) : undefined;
  if (session) session.used = Date.now();
  return session;
}

/**
 * A を更新する（P-18）。使い回すと、ログインサーバーがログインごと止めるので、セッションごとに 1 つしか走らせない。
 * 更新にもクライアント認証が要るので、更新のトークンを盗んでも、顧客のアプリの身元がなければ使えない（D31）。
 */
function renew(session: Session): Promise<void> {
  session.renewing ??= (async () => {
    if (!session.refresh) throw new LoginExpired("更新のトークンがない");
    const tokens = await oidc.refreshTokenGrant(client(), session.refresh, undefined, { DPoP: session.dpop }).catch((e: Error) => {
      throw new LoginExpired(`更新できない: ${e.message}`);
    });
    session.access = tokens.access_token;
    session.refresh = tokens.refresh_token ?? session.refresh;
  })().finally(() => (session.renewing = undefined));
  return session.renewing;
}

/** CSRF の対策（RFC 10017 の 6.1.3.3 節）。SameSite=Strict に加え、事前確認が要るヘッダーと、自分の origin を求める。 */
function sameOrigin(c: Context): boolean {
  if (c.req.header("x-bff") !== "1") return false;
  const origin = c.req.header("origin");
  return origin === undefined || origin === cfg().appOrigin;
}

async function startLogin(c: Context, kind: LoginState["kind"], extra: Pick<LoginState, "sid" | "inbox" | "register" | "remove"> = {}) {
  const config = client();
  const login: LoginState = { kind, verifier: oidc.randomPKCECodeVerifier(), state: random(), nonce: random(), ...extra, at: Date.now() };
  const id = random();
  logins.set(id, login);
  setCookie(c, LOGIN, id, { ...COOKIE, maxAge: 600 });
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: `${cfg().appOrigin}/callback`,
    scope: kind === "apply" ? "openid apply" : "openid passkeys",
    code_challenge: await oidc.calculatePKCECodeChallenge(login.verifier),
    code_challenge_method: "S256",
    state: login.state,
    nonce: login.nonce,
    ...(kind === "apply" ? { authorization_details: JSON.stringify(cfg().terms) } : { prompt: "none" }),
    // passkey の作成を頼まれたときは、ログインサーバーの画面で登録してもらう（Keycloak の AIA。D-42、D-43）
    ...(login.register ? { kc_action: "webauthn-register-passwordless" } : {}),
    // 削除を頼まれたときは、ログインサーバーが確認の画面を出し、本人に確かめてから消す（Keycloak の delete_credential。D-43）
    ...(login.remove ? { kc_action: `delete_credential:${login.remove}` } : {}),
  });
  return c.redirect(url.href, 302);
}

/** 認可サーバーを、P と DPoP の proof で呼ぶ。宛先と経路は決まったものだけ（D-42）。 */
async function callAuth(session: Session, p: string, method: "GET" | "POST", path: "/contacts/inbox" | "/passkeys/mine", body?: unknown) {
  const { authUrl, authOrigin } = cfg();
  const url = `${authOrigin}${path}`;
  return egressFetch(authUrl)(url, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      accept: "application/json",
      // 認可サーバー（Spring）は、転送のヘッダーで自分の URL を組み立て、DPoP の htu と照らす。出口の Envoy までは平文なので、
      // 相手まで TLS で届くことを明示する。Spring は X-Forwarded-Proto があるとポートを空にするので、ポートも明示する（F-G90）
      "x-forwarded-proto": "https",
      "x-forwarded-port": new URL(authOrigin).port,
      authorization: `DPoP ${p}`,
      dpop: await proof(session, method, url, p),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }).catch(() => undefined);
}

/** 受信箱の番号を、本人の連絡先として、認可サーバーに登録する（D-26）。 */
async function registerInbox(session: Session, p: string, inbox: string): Promise<boolean> {
  return Boolean((await callAuth(session, p, "POST", "/contacts/inbox", { inbox }))?.ok);
}

/** 本人の passkey の一覧を、認可サーバーから読む（D-43）。読めなければ undefined。 */
async function readPasskeys(session: Session, p: string): Promise<Passkeys | undefined> {
  const res = await callAuth(session, p, "GET", "/passkeys/mine");
  return res?.ok ? ((await res.json()) as Passkeys) : undefined;
}

export function addBff(app: Hono) {
  // ログインへ送る（A を受け取る）。端末の受信箱の番号と、passkey を作るかを受け取る
  app.get("/bff/login", (c) => {
    const inbox = c.req.query("inbox");
    const remove = c.req.query("delete");
    return startLogin(c, "apply", {
      inbox: inbox && INBOX.test(inbox) ? inbox : undefined,
      ...(remove && CREDENTIAL_REF.test(remove) ? { remove } : { register: c.req.query("register") === "1" }),
    });
  });

  /** 戻り先。認可コードを、JWT-SVID のクライアント認証と DPoP で替える。奪われた認可コードは、顧客のアプリの身元がなければ替えられない。 */
  app.get("/callback", async (c, next) => {
    const url = new URL(c.req.url, cfg().appOrigin);
    if (!url.searchParams.has("code") && !url.searchParams.has("error")) return next();
    const id = getCookie(c, LOGIN);
    const login = id ? logins.get(id) : undefined;
    if (id) logins.delete(id);
    deleteCookie(c, LOGIN, COOKIE);
    const fail = (message: string) => c.redirect(`/?login_error=${encodeURIComponent(message)}`, 302);
    if (!login) return fail("ログインの情報がない");
    if (url.searchParams.has("error")) return fail(`ログインできない: ${url.searchParams.get("error")}`);
    try {
      const existing = login.sid ? sessions.get(login.sid) : undefined;
      const keys = existing?.keys ?? ((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair);
      const config = client();
      const dpop = existing?.dpop ?? oidc.getDPoPHandle(config, keys);
      const callback = new URL(`${cfg().appOrigin}/callback${url.search}`);
      const tokens = await oidc.authorizationCodeGrant(config, callback, { pkceCodeVerifier: login.verifier, expectedState: login.state, expectedNonce: login.nonce, idTokenExpected: true }, undefined, { DPoP: dpop });
      if (!tokens.id_token) return fail("ID トークンを受け取れない");
      const { sub } = await checkIdToken(tokens.id_token, login.nonce);
      if (login.kind === "passkeys") {
        if (!existing || existing.sub !== sub) return fail("ログイン中の利用者と違う");
        // P で、端末の受信箱の番号を、本人の連絡先として登録する（D-26、D-37）。P は持ち続けない
        if (login.inbox) existing.inboxRegistered = await registerInbox(existing, tokens.access_token, login.inbox);
        // 本人の passkey の一覧も、同じ P で読む。画面は、端末に一覧を伝え、空なら作成を促す（D-43）
        existing.passkeys = await readPasskeys(existing, tokens.access_token);
        return c.redirect("/", 302);
      }
      const sid = random();
      const now = Date.now();
      // passkey の作成か削除を頼んだときは、ログインサーバーが結果（success、cancelled、error）を戻り先に付ける。取り消しや失敗でも、ログインは済んでいる
      const status = passkeyResult(url.searchParams.get("kc_action_status"));
      const passkeyAction: PasskeyAction | undefined = login.register ? { action: "create", status } : login.remove ? { action: "delete", status } : undefined;
      sessions.set(sid, { sub, idToken: tokens.id_token, keys, dpop, access: tokens.access_token, refresh: tokens.refresh_token, inboxRegistered: false, passkeyAction, created: now, used: now });
      setCookie(c, SESSION, sid, COOKIE);
      // 続けて、受信箱の登録に使う P を受け取る
      return startLogin(c, "passkeys", { sid, inbox: login.inbox });
    } catch (e) {
      return fail(`ログインできない: ${(e as Error).message}`);
    }
  });

  /** 画面に渡すのは、利用者の名前と、受信箱を登録できたかと、passkey の登録の結果と一覧だけ。トークンは渡さない。 */
  app.get("/bff/session", (c) => {
    const session = current(c);
    if (!session) return c.json({ error: "ログインしていない" }, 401);
    // passkey の作成か削除の結果は、ログインの後に 1 度だけ渡す
    const passkeyAction = session.passkeyAction;
    session.passkeyAction = undefined;
    return c.json({ sub: session.sub, inboxRegistered: session.inboxRegistered, ...(passkeyAction ? { passkeyAction } : {}), ...(session.passkeys ? { passkeys: session.passkeys } : {}) });
  });

  /**
   * サインアウト（OpenID Connect の RP-Initiated Logout。D-33）。セッションを消し、画面には、ログインサーバーへ送る URL を返す。
   * ログインサーバーが再起動して鍵が替わると、前の ID トークンはエラーの画面になるので、確かめられるものだけを示す。
   */
  app.post("/bff/logout", async (c) => {
    if (!sameOrigin(c)) return c.json({ error: "要求の出どころを確かめられない" }, 403);
    const session = current(c);
    const sid = getCookie(c, SESSION);
    if (sid) sessions.delete(sid);
    deleteCookie(c, SESSION, COOKIE);
    const jwks = createRemoteJWKSet(new URL(`${cfg().loginUrl}/realms/insurer/protocol/openid-connect/certs`));
    return c.json({ url: await logoutUrl(session?.idToken, jwks) });
  });

  /**
   * 営業 AI エージェントとの AG-UI を、A と DPoP の proof を付けて中継する（D-29）。回の前に、A の残りが短ければ更新し、
   * 401 なら、1 度だけ更新して送り直す（P-18）。401 は受け口で断られるので、回は始まっていない。
   */
  app.post("/bff/agui", async (c) => {
    if (!sameOrigin(c)) return c.json({ error: "要求の出どころを確かめられない" }, 403);
    const session = current(c);
    if (!session) return c.json({ error: "ログインしていない" }, 401);
    const body = await c.req.text();
    const { agentUrl, agentOrigin } = cfg();
    const send = async () =>
      egressFetch(agentUrl)(`${agentOrigin}/agui`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "text/event-stream",
          authorization: `DPoP ${session.access}`,
          dpop: await proof(session, "POST", `${agentOrigin}/agui`, session.access),
        },
        body,
        signal: c.req.raw.signal,
      });
    try {
      if (needsRefresh(session.access, Date.now())) await renew(session);
      let res = await send();
      if (res.status === 401) {
        await res.body?.cancel();
        await renew(session);
        res = await send();
      }
      return new Response(res.body, { status: res.status, headers: { "content-type": res.headers.get("content-type") ?? "application/json", "cache-control": "no-cache" } });
    } catch (e) {
      if (e instanceof LoginExpired) return c.json({ error: "ログインの有効期間が切れた" }, 401);
      throw e;
    }
  });

}
