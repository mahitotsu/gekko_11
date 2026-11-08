// token-guard の DPoP の受け口の確かめ（営業 AI エージェント。G26）。proof の方式は、送信者の秘密鍵の署名（ES256）に限る。
// ログインサーバーの公開鍵（JWKS）は、テストの中の小さなサーバーが返す。
import { createHash, randomUUID } from "node:crypto";
import { serve, type ServerType } from "@hono/node-server";
import { Hono } from "hono";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, generateSecret, SignJWT, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ISSUER = "http://login.secure.localhost:8081/realms/insurer";
const URL_AGUI = "https://sales-agent.secure.svc:8443/agui";
let server: ServerType;
let signToken: (jkt: string) => Promise<string>;
let check: typeof import("../src/verify.ts");

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256" };
  const app = new Hono().get("/certs", (c) => c.json({ keys: [jwk] }));
  server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" });
  await new Promise((r) => server.once("listening", r));
  const port = (server.address() as { port: number }).port;
  Object.assign(process.env, {
    SERVICE: "sales-agent",
    NAMESPACE: "secure",
    ISSUER,
    INGRESS_PROOF: "dpop",
    ALLOWED_CALLERS: "customer-app",
    JWKS_URL: `http://127.0.0.1:${port}/certs`,
  });
  signToken = (jkt) =>
    new SignJWT({ sub: "alice", aud: "sales-agent", cnf: { jkt } })
      .setProtectedHeader({ alg: "RS256", kid: "k1", typ: "at+jwt" })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  check = await import("../src/verify.ts");
});

afterAll(() => server.close());

const ath = (token: string) => createHash("sha256").update(token).digest("base64url");
const xfcc = "Hash=ab;URI=spiffe://gekko11.internal/ns/secure/sa/customer-app";

/** proof を、与えた鍵と方式で作り、受け口に出す。 */
async function attempt(alg: string, key: CryptoKey | Uint8Array, jwk: JWK) {
  const token = await signToken(await calculateJwkThumbprint(jwk));
  const dpop = await new SignJWT({ htm: "POST", htu: URL_AGUI, ath: ath(token), jti: randomUUID() })
    .setProtectedHeader({ alg, typ: "dpop+jwt", jwk })
    .setIssuedAt()
    .sign(key);
  try {
    await check.checkIngress({ method: "POST", url: URL_AGUI, authorization: `DPoP ${token}`, dpop, xfcc });
    return "通る";
  } catch (e) {
    return (e as Error).message;
  }
}

describe("DPoP の proof の方式（G26）", () => {
  it("顧客のアプリの BFF と同じ ES256 の proof は通る", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    expect(await attempt("ES256", privateKey, await exportJWK(publicKey))).toBe("通る");
  });

  it("共有の鍵の HS256 の proof は、トークンがその鍵に結ばれていても断る", async () => {
    const secret = (await generateSecret("HS256", { extractable: true })) as Uint8Array | CryptoKey;
    const jwk = await exportJWK(secret);
    expect(await attempt("HS256", secret, jwk)).toMatch(/alg が ES256 でない/);
  });
});
