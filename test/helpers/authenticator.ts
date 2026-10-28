// テスト用のソフトウェア認証器。本物のパスキー(Windows Hello 等)の代わりに、
// 登録(attestation: none)とサイン(assertion)の JSON を自前で作る。
import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";

const b64u = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest();

// 必要最小限の CBOR(整数・バイト列・文字列・マップ)
function cbor(v: unknown): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  };
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error("unsupported cbor");
}

export class SoftAuthenticator {
  readonly credId = randomBytes(16);
  private priv: KeyObject;
  private pub: KeyObject;
  private counter = 0;
  constructor(private rpId = "localhost") {
    ({ privateKey: this.priv, publicKey: this.pub } = generateKeyPairSync("ec", { namedCurve: "P-256" }));
  }
  get id() { return b64u(this.credId); }

  // パスキーの登録(navigator.credentials.create の結果)
  register(challenge: string, origin: string) {
    const jwk = this.pub.export({ format: "jwk" });
    const cose = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
    const idLen = Buffer.alloc(2); idLen.writeUInt16BE(this.credId.length);
    const authData = Buffer.concat([sha256(this.rpId), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen, this.credId, cose]);
    const attestationObject = cbor(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false }));
    return {
      id: this.id, rawId: this.id, type: "public-key", clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ["internal"] },
    };
  }

  // サイン(navigator.credentials.get の結果)。challenge は署名する内容のハッシュ。
  sign(challenge: string, origin: string) {
    this.counter += 1;
    const cnt = Buffer.alloc(4); cnt.writeUInt32BE(this.counter);
    const authData = Buffer.concat([sha256(this.rpId), Buffer.from([0x05]), cnt]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
    const signature = createSign("sha256").update(Buffer.concat([authData, sha256(clientDataJSON)])).sign(this.priv);
    return {
      id: this.id, rawId: this.id, type: "public-key", clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: b64u(Buffer.from("user")) },
    };
  }
}
