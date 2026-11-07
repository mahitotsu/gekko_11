// ログイン（D-41）。OAuth は BFF（顧客のアプリの配信元のサーバー）が機密クライアントとして行い、画面はトークンも鍵も持たない。
// 画面は、BFF のセッションの Cookie（HttpOnly）で、ログインの有無と利用者の名前だけを知る。

export interface Config {
  appOrigin: string;
  rpId: string;
  terms: unknown;
}

export interface Session {
  sub: string;
  /** passkey の登録に使う P を、BFF が持っているか（D-37）。 */
  passkeyReady: boolean;
}

/** BFF の受け口を呼ぶ。CSRF の対策として、事前確認が要るヘッダーを付ける（RFC 10017 の 6.1.3.3 節）。 */
export const bff = (path: string, init: RequestInit = {}) =>
  fetch(path, { ...init, credentials: "same-origin", headers: { "x-bff": "1", ...(init.headers as Record<string, string>) } });

export const auth = {
  /** A を受け取るログイン。BFF が、取決めの範囲を一緒に求める。 */
  startLogin: () => location.assign("/bff/login"),
  /** ログインしたまま、利用者の操作なしで、passkey の登録に使う P を BFF が受け取る（D-37）。 */
  startPasskeyToken: () => location.assign("/bff/login/passkeys"),
  async session(): Promise<Session | undefined> {
    const res = await bff("/bff/session");
    return res.ok ? ((await res.json()) as Session) : undefined;
  },
  /** サインアウト（D-33）。BFF がセッションを消し、ログインサーバーへ送る URL を返す。 */
  async signOut() {
    const res = await bff("/bff/logout", { method: "POST" });
    const { url } = (await res.json()) as { url: string };
    location.assign(url);
  },
};

export type Auth = typeof auth;
