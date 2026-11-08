// ログイン（D-41、D-42）。OAuth は BFF（顧客のアプリの配信元のサーバー）が機密クライアントとして行い、画面はトークンも鍵も持たない。
// 画面は、BFF のセッションの Cookie（HttpOnly）で、ログインの有無と利用者の名前だけを知る。
// passkey は、ログインと申込みの署名で同じものを使う。登録はログインサーバーの画面で行う。作るかは、保険会社にある一覧を見て、利用者が決める（D-43）。

export interface Config {
  appOrigin: string;
  rpId: string;
  terms: unknown;
}

export interface Session {
  sub: string;
  /** 端末の受信箱の番号を、BFF が認可サーバーに登録できたか（D-26）。 */
  inboxRegistered: boolean;
  /** passkey の作成か削除を頼んだときだけ、その結果が付く（D-42、D-43）。 */
  passkeyAction?: { action: "create" | "delete"; status: "success" | "cancelled" | "error" };
  /**
   * 保険会社（ログインサーバー）にある本人の passkey の一覧。読めなかったときは付かない（D-43）。
   * id は passkey の識別子、ref はログインサーバーの中の ID（消すときに渡す）。
   */
  passkeys?: { userHandle: string; passkeys: { id: string; ref: string; label: string; created: number }[] };
}

/**
 * この端末の情報。受信箱の番号（D-26）だけを持つ。この端末に passkey があるかは、ブラウザが教えないので、覚えない（D-43）。
 */
export interface Device {
  inbox: string;
}

const DEVICE = "device";

const random = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** この端末の情報。なければ作る。受信箱の番号は、推測できない値にする（128 ビット）。 */
export function device(): Device {
  const saved = localStorage.getItem(DEVICE);
  if (saved) return { inbox: (JSON.parse(saved) as Device).inbox };
  const created: Device = { inbox: random() };
  localStorage.setItem(DEVICE, JSON.stringify(created));
  return created;
}

/**
 * この端末で、最後に申込みの署名に使えた passkey の識別子（D-43）。一覧で、この端末のものに印を付ける。
 * 署名に使えたことが分かるのは、使った後だけである。印のないものは、ほかの端末か、使えなくなった端末のもの。
 */
export const usedPasskey = {
  get: (sub: string) => localStorage.getItem(`used-passkey:${sub}`) ?? undefined,
  set: (sub: string, id: string) => localStorage.setItem(`used-passkey:${sub}`, id),
};

/** BFF の受け口を呼ぶ。CSRF の対策として、事前確認が要るヘッダーを付ける（RFC 10017 の 6.1.3.3 節）。 */
export const bff = (path: string, init: RequestInit = {}) =>
  fetch(path, { ...init, credentials: "same-origin", headers: { "x-bff": "1", ...(init.headers as Record<string, string>) } });

export const auth = {
  /** ログインへ送る。createPasskey が真なら、ログインの後に、ログインサーバーの画面で passkey を作ってもらう（D-42、D-43）。 */
  startLogin(createPasskey = false) {
    location.assign(`/bff/login?${new URLSearchParams({ inbox: device().inbox, ...(createPasskey ? { register: "1" } : {}) })}`);
  },
  /** 本人の passkey を消すよう、ログインサーバーに頼む。ログインサーバーが確認の画面で確かめてから消す（D-43）。 */
  deletePasskey(ref: string) {
    location.assign(`/bff/login?${new URLSearchParams({ inbox: device().inbox, delete: ref })}`);
  },
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
