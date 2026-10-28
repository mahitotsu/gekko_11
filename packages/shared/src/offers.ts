import { SignJWT, createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { urls } from "./config.js";
import { challengeOf } from "./canonical.js";
import type { OfferSet } from "./models.js";

export const OFFER_TYP = "offer+jwt";
export const OFFER_ISSUER = "insurer-backend";

export interface OfferPayload extends JWTPayload, OfferSet {
  offerSetId: string;
  nonce: string;
}

// 提示集合の識別子(仮称)。案の全体を正規化したハッシュ。
export const offerSetId = (set: OfferSet) => challengeOf(set);

type SignKey = Parameters<SignJWT["sign"]>[0];
type VerifyKey = Parameters<typeof jwtVerify>[1];

// 保険会社が、顧客に示す案の一式に署名する。typ を offer+jwt にして、票(at+jwt)と取り違えられないようにする。
export function signOfferSet(key: SignKey, kid: string, set: OfferSet, nonce: string, ttlSec = 600): Promise<string> {
  return new SignJWT({ customer: set.customer, plans: set.plans, offerSetId: offerSetId(set), nonce })
    .setProtectedHeader({ alg: "ES256", kid, typ: OFFER_TYP })
    .setIssuer(OFFER_ISSUER)
    .setIssuedAt()
    .setExpirationTime(`${ttlSec}s`)
    .sign(key);
}

// 提示の署名を検証する。alg と typ を固定し、案の一式から識別子を作り直して照合する。
export async function verifyOfferSet(jws: string, key: VerifyKey): Promise<OfferPayload> {
  const { payload } = await jwtVerify(jws, key as never, { algorithms: ["ES256"], typ: OFFER_TYP, issuer: OFFER_ISSUER });
  const p = payload as OfferPayload;
  if (p.offerSetId !== offerSetId({ customer: p.customer, plans: p.plans })) throw new Error("提示集合の識別子が案の内容と一致しません");
  return p;
}

const offerJwks = createRemoteJWKSet(new URL(`${urls.insurerBackend}/offers-jwks.json`), { cooldownDuration: 0 });
// 顧客のアプリが使う。保険会社の公開鍵を取りに行って検証する。
export const verifyOfferSetRemote = (jws: string) => verifyOfferSet(jws, offerJwks);
