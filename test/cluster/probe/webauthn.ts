// テスト用のソフトウェア認証器。本物の passkey の代わりに、登録（attestation: none）と署名（assertion）の JSON を作る。
// 状態（鍵と回数）を JSON にして持ち回れるので、手元のテストと、クラスタの中の probe の両方から使える。
import { createHash, createPrivateKey, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import canonicalize from "canonicalize";

const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest();

/** JCS（RFC 8785）で正規化した内容の SHA-256。passkey に署名させる challenge（D-1）。 */
export function challengeOf(value: unknown): string {
  const c = canonicalize(value);
  if (!c) throw new Error("正規化できない");
  return b64u(sha256(c));
}

/** 必要最小限の CBOR（整数、バイト列、文字列、マップ）。 */
function cbor(v: unknown): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  };
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") {
    const b = Buffer.from(v);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error("unsupported cbor");
}

export interface AuthenticatorState {
  credId: string;
  privateJwk: Record<string, string>;
  counter: number;
}

export function newAuthenticator(): AuthenticatorState {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { credId: b64u(randomBytes(16)), privateJwk: privateKey.export({ format: "jwk" }) as Record<string, string>, counter: 0 };
}

/** 登録（navigator.credentials.create の結果）。 */
export function register(state: AuthenticatorState, rpId: string, challenge: string, origin: string) {
  const { x, y } = state.privateJwk;
  const cose = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(x!, "base64url")], [-3, Buffer.from(y!, "base64url")]]));
  const id = Buffer.from(state.credId, "base64url");
  const idLen = Buffer.alloc(2);
  idLen.writeUInt16BE(id.length);
  const authData = Buffer.concat([sha256(rpId), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen, id, cose]);
  const attestationObject = cbor(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
  const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false }));
  return {
    id: state.credId,
    rawId: state.credId,
    type: "public-key",
    clientExtensionResults: {},
    response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ["internal"] },
  };
}

/** 署名（navigator.credentials.get の結果）。challenge は、署名する内容のハッシュ。状態の回数を進める。 */
export function sign(state: AuthenticatorState, rpId: string, challenge: string, origin: string) {
  state.counter += 1;
  const cnt = Buffer.alloc(4);
  cnt.writeUInt32BE(state.counter);
  const authData = Buffer.concat([sha256(rpId), Buffer.from([0x05]), cnt]);
  const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
  const key = createPrivateKey({ key: state.privateJwk, format: "jwk" });
  const signature = createSign("sha256").update(Buffer.concat([authData, sha256(clientDataJSON)])).sign(key);
  return {
    id: state.credId,
    rawId: state.credId,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64u(clientDataJSON),
      authenticatorData: b64u(authData),
      signature: b64u(signature),
      userHandle: b64u(Buffer.from("user")),
    },
  };
}
