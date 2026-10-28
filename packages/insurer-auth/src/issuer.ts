import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";
import { ISSUER, audiences, modeOf, type Actor, type InsuranceTerms, type VerifiedClaims } from "@gekko/shared";

export const { publicKey, privateKey } = await generateKeyPair("ES256");
const kid = "insurer-auth-key-1";
export const jwk: JWK = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };

export interface IssueInput {
  sub: string;
  aud: string;
  clientId: string;
  scope: string;
  terms?: InsuranceTerms[];
  act?: Actor;
  acr?: string;
  authTime?: number;
  verified?: VerifiedClaims;
}

// トークンを発行する。良い発行は「宛先を1つに絞り、短命で、typ を付け、act を残す」。
// 悪い発行は宛先・期限・act のどれかを怠る。受け取る側がどれだけ丁寧に検証しても防げない例を作るため。
// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
export async function issue(input: IssueInput): Promise<string> {
  const bad = modeOf("auth") === "bad";
  const claims: Record<string, unknown> = { scope: input.scope, client_id: input.clientId };
  if (input.terms) claims.authorization_details = input.terms;
  if (input.act && !bad) claims.act = input.act; // 悪い発行は act を落とす
  if (input.acr) claims.acr = input.acr;
  if (input.authTime) claims.auth_time = input.authTime;
  if (input.verified) claims.verified_claims = input.verified;
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid, typ: "at+jwt" })
    .setIssuer(ISSUER)
    .setSubject(input.sub)
    // 悪い発行は全窓口を宛先にしてしまう(どの窓口でも通用する万能トークン)
    .setAudience(bad ? Object.values(audiences) : input.aud)
    .setIssuedAt()
    .setExpirationTime(bad ? "24h" : "10m")
    .setJti(crypto.randomUUID())
    .sign(privateKey);
}

// ID トークン(OIDC)。本人が誰かを顧客のアプリに伝えるトークンで、API の呼び出しには使わない。typ は付けない。
// 悪い発行は、aud に API の識別子まで入れてしまう(画面と API で識別子を使い回した設定)。
export async function issueIdToken(sub: string, clientId: string): Promise<string> {
  const bad = modeOf("auth") === "bad";
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid })
    .setIssuer(ISSUER)
    .setSubject(sub)
    .setAudience(bad ? [clientId, ...Object.values(audiences)] : clientId)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
}
