import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { describe, expect, it } from "vitest";
import { confirmationOf, verifyIdToken, verifyOffer, type Offer } from "../web/checks.ts";
import { challengeOf } from "../web/codec.ts";

const ISSUER = "http://auth.secure.localhost:8081";

async function keys(alg: "RS256" | "ES256") {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const jwk: JWK = { ...(await exportJWK(publicKey)), alg, kid: "k1" };
  return { privateKey, jwks: createLocalJWKSet({ keys: [jwk] }) };
}

describe("ID トークンを確かめる（D21）", async () => {
  const { privateKey, jwks } = await keys("RS256");
  const idToken = (claims: Record<string, unknown>, aud = "customer-app", exp = "5m") =>
    new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(ISSUER).setSubject("alice").setAudience(aud).setIssuedAt().setExpirationTime(exp).sign(privateKey);
  const expect_ = { issuer: ISSUER, clientId: "customer-app", nonce: "n-1" };

  it("署名、iss、宛先、期限、nonce が合えば、本人を返す", async () => {
    expect(await verifyIdToken(await idToken({ nonce: "n-1" }), jwks, expect_)).toEqual({ sub: "alice" });
  });

  it("別のログインの nonce、別の宛先、期限切れ、別の鍵の署名は拒む", async () => {
    await expect(verifyIdToken(await idToken({ nonce: "n-2" }), jwks, expect_)).rejects.toThrow("nonce");
    await expect(verifyIdToken(await idToken({ nonce: "n-1" }, "sales-agent"), jwks, expect_)).rejects.toThrow();
    await expect(verifyIdToken(await idToken({ nonce: "n-1" }, "customer-app", "-1m"), jwks, expect_)).rejects.toThrow();
    const other = await keys("RS256");
    await expect(verifyIdToken(await idToken({ nonce: "n-1" }), other.jwks, expect_)).rejects.toThrow();
  });
});

describe("案の署名を確かめてから示す（D22）", async () => {
  const { privateKey, jwks } = await keys("ES256");
  const plans = [
    { id: "fixed-60", name: "確定年金 10年・年額60万円", kind: "fixed", benefit: 600_000, monthly: 20_000 },
    { id: "life-120", name: "終身年金・年額120万円", kind: "lifetime", benefit: 1_200_000, monthly: 60_000 },
  ];
  const offerSetId = await challengeOf({ customer: "alice", plans });
  const exp = Math.floor(Date.now() / 1000) + 300;
  const jws = await new SignJWT({ customer: "alice", plans, offerSetId, nonce: "n-1" })
    .setProtectedHeader({ alg: "ES256", typ: "offer+jwt", kid: "k1" })
    .setIssuer("insurer-backend")
    .setExpirationTime(exp)
    .sign(privateKey);
  const offer: Offer = { offerJws: jws, offerSet: { customer: "alice", plans }, offerSetId, nonce: "n-1", expiresAt: exp };

  it("署名された中身を返す", async () => {
    expect(await verifyOffer(offer, jwks, "alice")).toEqual({ offer, tampered: false });
  });

  it("運ばれた案の一覧が、署名された中身と違えば、すり替えを知らせ、署名された案だけを返す", async () => {
    const fake = { id: "fixed-gold", name: "偽の案", kind: "fixed", benefit: 1_200_000, monthly: 9_000 };
    const r = await verifyOffer({ ...offer, offerSet: { customer: "alice", plans: [...plans, fake] } }, jwks, "alice");
    expect(r.tampered).toBe(true);
    expect(r.offer.offerSet.plans.map((p) => p.id)).toEqual(["fixed-60", "life-120"]);
  });

  it("本人宛てでない提示と、別の鍵の署名は拒む", async () => {
    await expect(verifyOffer(offer, jwks, "bob")).rejects.toThrow("本人宛て");
    const other = await keys("ES256");
    await expect(verifyOffer(offer, other.jwks, "alice")).rejects.toThrow();
  });
});

describe("確認画面を、署名する内容から作る（D23）", () => {
  it("説明文ではなく、申込みの内容を行にする", () => {
    const plan = { id: "life-120", name: "終身年金・年額120万円", kind: "lifetime", benefit: 1_200_000, monthly: 60_000 };
    const rows = confirmationOf({
      intent: { customer: "alice", offerSetId: "s", planId: "life-120", wish: "備えたい", nonce: "n", expiresAt: 1 },
      application: { customer: "alice", plan, offerSetId: "s", nonce: "n", expiresAt: 1 },
      summary: "「確定年金 10年・年額60万円」（月額の保険料 20,000 円）で用意しました",
    });
    const value = (key: string) => rows.find((r) => r.key === key)?.value;
    expect(value("plan-name")).toBe("終身年金・年額120万円");
    expect(value("monthly")).toBe("60,000 円");
    expect(rows.some((r) => r.value.includes("20,000"))).toBe(false);
  });
});
