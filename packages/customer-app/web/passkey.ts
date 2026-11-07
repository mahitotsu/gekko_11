// passkey（D-18）。鍵は認証器が持つ。作成と署名は @simplewebauthn/browser に任せ、署名する challenge は、内容のハッシュ（D-1）にする。
import { startAuthentication, startRegistration, type PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/browser";

export const createPasskey = (options: PublicKeyCredentialCreationOptionsJSON) => startRegistration({ optionsJSON: options });

/** passkey で、内容のハッシュ（challenge）に署名する。 */
export const signWithPasskey = (challenge: string, rpId: string, credentialId: string) =>
  startAuthentication({
    optionsJSON: { challenge, rpId, userVerification: "required", allowCredentials: [{ type: "public-key", id: credentialId }] },
  });
