// ログインと更新（D-12、P-18）。認可コードと PKCE、DPoP の取り出せない鍵、更新は oidc-client-ts に任せる。
// oidc-client-ts は ID トークンの署名を確かめないので、D21 は、ログインの後に checks.ts で確かめる（D-40）。
// A（申込み）と P（passkey の登録）は、同じログインの、宛先の違うトークンなので、別の UserManager で持つ。
import { compactVerify, createRemoteJWKSet } from "jose";
import { ErrorResponse, IndexedDbDPoPStore, UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import { needsRefresh, verifyIdToken } from "./checks.ts";
import { randomB64u } from "./codec.ts";

export interface Config {
  /** ログインサーバーの iss。 */
  issuer: string;
  /** 認可サーバーの公開名（passkey と受信箱の登録）。 */
  authOrigin: string;
  agentOrigin: string;
  appOrigin: string;
  rpId: string;
  clientId: string;
  terms: unknown;
}

/** A を更新できない。ログインし直すしかない。 */
export class LoginExpired extends Error {}

type LoginKind = "apply" | "passkeys";

export interface Session {
  sub: string;
}

export function createAuth(cfg: Config, enabled: (id: string) => boolean) {
  const oidc = `${cfg.issuer}/protocol/openid-connect`;
  const jwks = () => createRemoteJWKSet(new URL(`${oidc}/certs`));
  const stateStore = new WebStorageStateStore({ store: sessionStorage });
  const manager = (kind: LoginKind) =>
    new UserManager({
      authority: cfg.issuer,
      client_id: cfg.clientId,
      redirect_uri: `${cfg.appOrigin}/callback`,
      response_type: "code",
      scope: kind === "apply" ? "openid apply" : "openid passkeys",
      // 発見の文書を読みに行かず、決まった宛先だけを使う
      metadata: { issuer: cfg.issuer, authorization_endpoint: `${oidc}/auth`, token_endpoint: `${oidc}/token`, jwks_uri: `${oidc}/certs` },
      stateStore,
      userStore: new WebStorageStateStore({ prefix: `oidc.${kind}.`, store: sessionStorage }),
      dpop: { bind_authorization_code: false, store: new IndexedDbDPoPStore() },
      loadUserInfo: false,
      automaticSilentRenew: false,
      monitorSession: false,
    });
  const apply = manager("apply");
  const passkeys = manager("passkeys");
  const managers = { apply, passkeys };

  /** ログインへ送る。D21 を外した悪い実装は、nonce を付けず、別人の ID トークンも受け取ってしまう。 */
  async function start(kind: LoginKind, extraQueryParams: Record<string, string>, prompt?: string) {
    const nonce = enabled("D21") ? randomB64u(16) : undefined;
    sessionStorage.setItem("login", JSON.stringify({ kind, nonce }));
    await managers[kind].signinRedirect({ nonce, prompt, extraQueryParams });
  }

  let renewing: Promise<void> | undefined;

  return {
    /** A を受け取るログイン。取決めの範囲を一緒に求める。 */
    startLogin: () => start("apply", { authorization_details: JSON.stringify(cfg.terms) }),
    /** ログインしたまま、利用者の操作なしで、passkey の登録に使う P を受け取る（D-37）。 */
    startPasskeyToken: () => start("passkeys", {}, "none"),

    /** 戻り先を片付ける。A を受け取ったときは、続けて P を求めるので、真を返す（画面は作らない）。 */
    async finishLogin(): Promise<boolean> {
      const login = JSON.parse(sessionStorage.getItem("login") ?? "null") as { kind: LoginKind; nonce?: string } | null;
      const url = location.href;
      history.replaceState(null, "", "/");
      if (!login) throw new Error("ログインの情報がない");
      const user = await managers[login.kind].signinCallback(url);
      if (!user?.id_token) throw new Error("ID トークンを受け取れない");
      if (enabled("D21")) {
        await verifyIdToken(user.id_token, jwks(), { issuer: cfg.issuer, clientId: cfg.clientId, nonce: login.nonce ?? "" }).catch(async (e: Error) => {
          await managers[login.kind].removeUser();
          throw e;
        });
      }
      sessionStorage.removeItem("login");
      if (login.kind === "passkeys") return false;
      await start("passkeys", {}, "none");
      return true;
    },

    async session(): Promise<Session | undefined> {
      const user = await apply.getUser();
      return user ? { sub: user.profile.sub } : undefined;
    },

    /** P がまだ使えるか。 */
    async passkeyUser(): Promise<User | null> {
      const user = await passkeys.getUser();
      return user && !needsRefresh(user.access_token, Date.now(), 5000) ? user : null;
    },

    passkeyProof: async (url: string, method: string, user: User) => (await passkeys.dpopProof(url, user, method))!,

    /** 営業 AI エージェントを呼ぶ今の A と、その DPoP の proof。 */
    async agentHeaders(url: string): Promise<Record<string, string>> {
      const user = await apply.getUser();
      if (!user) throw new LoginExpired("ログインしていない");
      return { authorization: `DPoP ${user.access_token}`, dpop: (await apply.dpopProof(url, user, "POST"))! };
    },

    /** 回を始める前に、A の残りが短ければ更新する（P-18）。 */
    async tokenIsShort(): Promise<boolean> {
      const user = await apply.getUser();
      return !user || needsRefresh(user.access_token, Date.now());
    },

    /**
     * A を更新する（P-18）。使い回すと、ログインサーバーがログインごと止めるので、同時に 1 つしか走らせない。
     * 更新するのは顧客のアプリだけで、更新のトークンは、営業 AI エージェントに渡さない。
     */
    renew(): Promise<void> {
      renewing ??= (async () => {
        const user = await apply.getUser();
        if (!user?.refresh_token) throw new LoginExpired("更新のトークンがない");
        await apply.signinSilent().catch((e: unknown) => {
          if (e instanceof ErrorResponse) throw new LoginExpired(`更新できない: ${e.error ?? e.message}`);
          throw e;
        });
      })().finally(() => (renewing = undefined));
      return renewing;
    },

    /**
     * サインアウト（OpenID Connect の RP-Initiated Logout。D-33）。手元のログインを消してから、ログインサーバーのログインも終わらせる。
     * ログインサーバーが再起動して鍵が替わると、前の ID トークンはエラーの画面になるので、確かめられるものだけを示す。
     * 示さなければ、ログインサーバーが確認の画面を出し、利用者の操作で終わる。
     */
    async signOut() {
      const user = await apply.getUser();
      await Promise.all([apply.removeUser(), passkeys.removeUser()]);
      const q = new URLSearchParams({ client_id: cfg.clientId, post_logout_redirect_uri: `${location.origin}/` });
      if (user?.id_token && (await compactVerify(user.id_token, jwks()).catch(() => undefined))) q.set("id_token_hint", user.id_token);
      location.assign(`${oidc}/logout?${q}`);
    },
  };
}

export type Auth = ReturnType<typeof createAuth>;
