// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from "jose";
import { ISSUER, urls } from "./config.js";
import type { InsuranceTerms } from "./models.js";

export interface Ticket extends JWTPayload {
  sub: string;
  scope?: string;
  act?: Actor;
  authorization_details?: InsuranceTerms[];
  client_id?: string;
  acr?: string;
  auth_time?: number;
  verified_claims?: VerifiedClaims; // 本人確認が済んだ属性(OIDC4IDA の最小形)
}
export interface VerifiedClaims {
  verification: { trust_framework: string; time: string; method: string };
  claims: { name: string };
}
export interface Actor {
  sub: string;
  act?: Actor;
}

export class VerifyError extends Error {}

const jwks = createRemoteJWKSet(new URL(`${urls.insurerAuth}/jwks.json`), { cooldownDuration: 0 });

export interface TicketChecks {
  signature: boolean; // 署名を検証するか(鍵は JWKS から取り、alg は ES256 に固定)
  audience?: string; // 指定すれば aud がこの値を含むことを確かめる
  expiry: boolean; // exp を確かめるか
  typ: boolean; // ヘッダーの typ が at+jwt か
}

const HUNDRED_YEARS = 60 * 60 * 24 * 365 * 100;

// 検証項目を個別に外せる。悪い実装を再現するための部品で、良い実装は verifyTicketGood を使う。
export async function verifyTicketWith(token: string, o: TicketChecks): Promise<Ticket> {
  try {
    if (!o.signature) return decodeJwt(token) as Ticket; // 署名を見ない(alg=none も通る)
    const { payload } = await jwtVerify(token, jwks, {
      algorithms: ["ES256"],
      issuer: ISSUER,
      audience: o.audience,
      typ: o.typ ? "at+jwt" : undefined,
      requiredClaims: o.expiry ? ["exp", "sub", "iat"] : ["sub"],
      clockTolerance: o.expiry ? 0 : HUNDRED_YEARS,
    });
    return payload as Ticket;
  } catch (e) {
    throw new VerifyError((e as Error).message);
  }
}

// 良い検証: 署名(alg固定) / iss / aud / 期限 / typ を全て見る。
export const verifyTicketGood = (token: string, audience: string) =>
  verifyTicketWith(token, { signature: true, audience, expiry: true, typ: true });

export function bearer(header: string | undefined): string {
  const m = header?.match(/^Bearer (.+)$/);
  if (!m) throw new VerifyError("Authorization: Bearer がありません");
  return m[1]!;
}

// act チェーンを「sales-agent → insurer-mcp」のような文字列にする(監査ログ用)
export function actChain(act?: Actor): string[] {
  const out: string[] = [];
  for (let a = act; a; a = a.act) out.push(a.sub);
  return out;
}
