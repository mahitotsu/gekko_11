// token-guard の受け口の確かめを、防御の ID ごとに外したときも含めて確かめる。
// 認可サーバーの公開鍵（JWKS）は、テストの中の小さなサーバーが返す。
import { serve, type ServerType } from "@hono/node-server";
import { Hono } from "hono";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ISSUER = "https://insurer-auth.secure.svc:8443";
let server: ServerType;
let sign: (claims: Record<string, unknown>, typ?: string) => Promise<string>;
let check: typeof import("../src/verify.ts");
let admin: string;

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256" };
  // 有効性の問い合わせは、sub が revoked のトークンだけを無効と答える
  const app = new Hono()
    .get("/oauth2/jwks", (c) => c.json({ keys: [jwk] }))
    .post("/oauth2/introspect", async (c) => {
      const token = String((await c.req.parseBody()).token);
      const sub = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()).sub;
      return c.json({ active: sub !== "revoked" });
    });
  server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" });
  await new Promise((r) => server.once("listening", r));
  const port = (server.address() as { port: number }).port;
  Object.assign(process.env, {
    SERVICE: "insurer-backend",
    NAMESPACE: "secure",
    ISSUER,
    INGRESS_PROOF: "mtls",
    ALLOWED_CALLERS: "insurer-mcp",
    AUTH_EGRESS_URL: `http://127.0.0.1:${port}`,
    TOKEN_GUARD_ADMIN_PORT: String(port + 1),
  });
  sign = (claims, typ = "at+jwt") =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "k1", typ })
      .setIssuer(ISSUER)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  check = await import("../src/verify.ts");
  const defenses = await import("../src/defenses.ts");
  const { config } = await import("../src/config.ts");
  defenses.startAdmin(port + 1, config.defenseIds);
  admin = `http://127.0.0.1:${port + 1}/defenses`;
});

afterAll(() => server.close());

const peerHash = "ab".repeat(32);
const x5t = Buffer.from(peerHash, "hex").toString("base64url");
const xfcc = (sa: string) => `Hash=${peerHash};URI=spiffe://gekko11.internal/ns/secure/sa/${sa}`;
const off = (ids: Record<string, string>) =>
  fetch(admin, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ off: ids }) });

async function refusal(token: string, sa = "insurer-mcp") {
  try {
    await check.checkIngress({ method: "POST", url: "https://x/hop", authorization: `Bearer ${token}`, xfcc: xfcc(sa) });
    return "通る";
  } catch (e) {
    return (e as Error).message;
  }
}

describe("受け口の確かめ（保険会社のシステム）", () => {
  it("宛先、typ、結び付け、呼ぶ相手を確かめる", async () => {
    await off({});
    const good = { sub: "alice", aud: "insurer-backend", cnf: { "x5t#S256": x5t } };
    expect(await refusal(await sign(good))).toBe("通る");
    expect(await refusal(await sign({ ...good, aud: "insurer-mcp" }))).toMatch(/確かめられない/);
    expect(await refusal(await sign(good, "JWT"))).toMatch(/確かめられない/);
    expect(await refusal(await sign({ ...good, cnf: { "x5t#S256": "other" } }))).toMatch(/結ばれていない/);
    expect(await refusal(await sign(good), "intruder")).toMatch(/呼んでよい相手ではない/);
    expect(await refusal(await sign({ ...good, sub: "revoked" }))).toMatch(/登録が外れている/);
  });

  it("外した防御の確かめだけが飛ぶ", async () => {
    await off({ D7: "off", D26: "off", D27: "off" });
    expect(await (await fetch(admin)).json()).toEqual({ off: { D7: "off", D26: "off", D27: "off" } });
    const stray = { sub: "alice", aud: "insurer-mcp" };
    expect(await refusal(await sign(stray), "intruder")).toBe("通る");
    expect(await refusal(await sign(stray, "JWT"), "intruder")).toMatch(/確かめられない/);
    expect((await off({ D99: "off" })).status).toBe(400);
    await off({ D10: "off" });
    expect(await refusal(await sign({ sub: "revoked", aud: "insurer-backend", cnf: { "x5t#S256": x5t } }))).toBe("通る");
    await off({});
  });
});
