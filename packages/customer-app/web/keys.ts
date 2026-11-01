// 端末に置く鍵（D-18）。DPoP の鍵は、WebCrypto で取り出せない鍵として作り、IndexedDB に置く。passkey は、認証器が持つ。
import { SignJWT, type JWK } from "jose";
import { b64u, fromB64u, sha256 } from "./codec.ts";

const DB = "gekko-customer-app";

function idb<T>(mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const req = run(open.result.transaction("keys", mode).objectStore("keys"));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    };
  });
}

/** DPoP の鍵の組。初めてなら作る。秘密鍵は取り出せない（extractable: false）。 */
export async function dpopKey(): Promise<CryptoKeyPair> {
  const saved = await idb<CryptoKeyPair | undefined>("readonly", (s) => s.get("dpop"));
  if (saved) return saved;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  await idb("readwrite", (s) => s.put(pair, "dpop"));
  return pair;
}

/** DPoP の proof（RFC 9449）。token があれば、ath を入れる。 */
export async function dpopProof(htm: string, htu: string, token?: string): Promise<string> {
  const pair = await dpopKey();
  const { kty, crv, x, y } = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JWK;
  return new SignJWT({ htm, htu, jti: crypto.randomUUID(), ...(token ? { ath: b64u(await sha256(token)) } : {}) })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: { kty, crv, x, y } })
    .setIssuedAt()
    .sign(pair.privateKey);
}

/** passkey の登録（navigator.credentials.create）。結果は、認可サーバーが読む JSON の形にする。 */
export async function createPasskey(options: {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  authenticatorSelection: AuthenticatorSelectionCriteria;
  attestation: AttestationConveyancePreference;
}) {
  const cred = (await navigator.credentials.create({
    publicKey: { ...options, challenge: fromB64u(options.challenge), user: { ...options.user, id: fromB64u(options.user.id) } },
  })) as PublicKeyCredential;
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: b64u(cred.rawId),
    type: cred.type,
    clientExtensionResults: {},
    response: { clientDataJSON: b64u(r.clientDataJSON), attestationObject: b64u(r.attestationObject), transports: r.getTransports?.() ?? [] },
  };
}

/** passkey で、内容のハッシュ（challenge）に署名する（navigator.credentials.get）。 */
export async function signWithPasskey(challenge: string, rpId: string, credentialId: string) {
  const cred = (await navigator.credentials.get({
    publicKey: { challenge: fromB64u(challenge), rpId, userVerification: "required", allowCredentials: [{ type: "public-key", id: fromB64u(credentialId) }] },
  })) as PublicKeyCredential;
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: b64u(cred.rawId),
    type: cred.type,
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64u(r.clientDataJSON),
      authenticatorData: b64u(r.authenticatorData),
      signature: b64u(r.signature),
      userHandle: r.userHandle ? b64u(r.userHandle) : null,
    },
  };
}
