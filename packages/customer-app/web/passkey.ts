// passkey での署名（D-1、D-42）。鍵は認証器が持ち、ログインと同じ passkey を使う。署名する challenge は、内容のハッシュにする。
// 使える passkey は、保険会社（ログインサーバー）にある本人の passkey に限る（D-43）。保険会社が忘れた古い passkey では署名させない。
import { startAuthentication } from "@simplewebauthn/browser";
import type { AuthenticatorTransportFuture } from "@simplewebauthn/browser";

/** 署名に使ってよい passkey。transports は、登録のときに認証器が答えた経路（internal、hybrid など）。 */
export interface AllowedPasskey {
  id: string;
  transports?: string[];
}

/**
 * passkey で、内容のハッシュ（challenge）に署名する。RP ID は、ログインサーバーと顧客のアプリの共通の親の名前である。
 * 各 passkey には、登録のときの経路を添える（WebAuthn の仕様が、RP に勧める。D-44）。
 */
export const signWithPasskey = (challenge: string, rpId: string, allowed: AllowedPasskey[]) =>
  startAuthentication({
    optionsJSON: {
      challenge,
      rpId,
      userVerification: "required",
      allowCredentials: allowed.map(({ id, transports }) => ({
        id,
        type: "public-key" as const,
        ...(transports?.length ? { transports: transports as AuthenticatorTransportFuture[] } : {}),
      })),
    },
  });

/**
 * 保険会社にある本人の passkey の一覧を、端末に伝える（WebAuthn の Signal API。D-43）。端末は、一覧にない古い passkey を消すか隠す。
 * 端末の処理は待たずに返る。対応していないブラウザでは何もしない。
 */
export function signalAccepted(rpId: string, userHandle: string, ids: string[]) {
  const signal = (PublicKeyCredential as unknown as { signalAllAcceptedCredentials?: (o: unknown) => Promise<void> }).signalAllAcceptedCredentials;
  if (typeof signal !== "function") return;
  signal.call(PublicKeyCredential, { rpId, userId: userHandle, allAcceptedCredentialIds: ids }).catch(() => undefined);
}
