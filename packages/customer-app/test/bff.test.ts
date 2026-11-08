import { generateKeyPair, SignJWT, createLocalJWKSet, exportJWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.ts";
import { egressFetch, logoutUrl, passkeyResult } from "../src/bff.ts";

beforeAll(() => {
  Object.assign(process.env, { ISSUER: "http://login.test/realms/insurer", APP_ORIGIN: "http://app.test" });
});

describe("BFF（D-41）", () => {
  it("ログインは、BFF が機密クライアントとして、PKCE、state、nonce、取決めの範囲を付けて送り、途中の状態は HttpOnly の Cookie にだけ置く", async () => {
    const res = await createApp().request("/bff/login");
    expect(res.status).toBe(302);
    const url = new URL(res.headers.get("location")!);
    expect(url.origin + url.pathname).toBe("http://login.test/realms/insurer/protocol/openid-connect/auth");
    const q = url.searchParams;
    expect([q.get("client_id"), q.get("code_challenge_method"), q.get("scope"), q.get("redirect_uri")]).toEqual(["customer-app", "S256", "openid apply", "http://app.test/callback"]);
    expect(q.get("state")).toBeTruthy();
    expect(q.get("nonce")).toBeTruthy();
    expect(JSON.parse(q.get("authorization_details")!)[0].type).toBe("insurance_application");
    const cookie = res.headers.get("set-cookie")!;
    expect(cookie).toMatch(/^__Host-Http-login=/);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/Secure/);
    expect(cookie).toMatch(/SameSite=Strict/);
  });

  it("この端末で初めてのログインでは、ログインサーバーに passkey の登録を頼み、端末の受信箱の番号を途中の状態に持つ（D-42、D-26）", async () => {
    const inbox = "A".repeat(22);
    const first = new URL((await createApp().request(`/bff/login?inbox=${inbox}&register=1`)).headers.get("location")!);
    expect(first.searchParams.get("kc_action")).toBe("webauthn-register-passwordless");
    const again = new URL((await createApp().request(`/bff/login?inbox=${inbox}`)).headers.get("location")!);
    expect(again.searchParams.has("kc_action")).toBe(false);
  });

  it("passkey の削除は、ログインサーバーの中の ID（UUID）のときだけ頼み、ほかの値はログインサーバーに渡さない（D-43）", async () => {
    const ref = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const ok = new URL((await createApp().request(`/bff/login?delete=${ref}`)).headers.get("location")!);
    expect(ok.searchParams.get("kc_action")).toBe(`delete_credential:${ref}`);
    const bad = new URL((await createApp().request("/bff/login?delete=x%3Bkc_action%3Dother")).headers.get("location")!);
    expect(bad.searchParams.has("kc_action")).toBe(false);
  });

  it("passkey の登録の結果は、ログインサーバーが付けた値だけを信じ、値がないか分からなければ失敗とみなす（D-42）", () => {
    expect([passkeyResult("success"), passkeyResult("cancelled"), passkeyResult("error"), passkeyResult(null), passkeyResult("x")]).toEqual(["success", "cancelled", "error", "error", "error"]);
  });

  it("CSRF の対策: 事前確認の要るヘッダーがないか、ほかの origin からの要求は断る", async () => {
    const app = createApp();
    expect((await app.request("/bff/agui", { method: "POST", body: "{}" })).status).toBe(403);
    expect((await app.request("/bff/agui", { method: "POST", body: "{}", headers: { "x-bff": "1", origin: "http://evil.test" } })).status).toBe(403);
    expect((await app.request("/bff/agui", { method: "POST", body: "{}", headers: { "x-bff": "1", origin: "http://app.test" } })).status).toBe(401);
  });

  it("ログインしていなければ、画面には利用者もトークンも返さない", async () => {
    const res = await createApp().request("/bff/session");
    expect(res.status).toBe(401);
    expect(await res.text()).not.toMatch(/eyJ/);
  });

  it("決まった経路だけを転送する（RFC 10017 の 6.1.3.6 節）", async () => {
    const app = createApp();
    expect((await app.request("/bff/passkeys/register/options", { method: "POST", headers: { "x-bff": "1" } })).status).toBe(404);
    expect((await app.request("/bff/agui", { method: "GET" })).status).toBe(404);
  });

  it("戻り先に、ログインの途中の状態がなければ、ログインの失敗として画面へ戻す", async () => {
    const res = await createApp().request("/callback?code=x&state=y");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toMatch(/^\/\?login_error=/);
  });

  it("サインアウトでは、確かめられる ID トークンだけを示す（D-33）", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(publicKey)), kid: "k", alg: "RS256" }] });
    const good = await new SignJWT({ sub: "alice" }).setProtectedHeader({ alg: "RS256", kid: "k" }).sign(privateKey);
    expect(new URL(await logoutUrl(good, jwks)).searchParams.get("id_token_hint")).toBe(good);
    // ログインサーバーが再起動して鍵が替わると、確かめられない。示さなければ、ログインサーバーが確認の画面を出す
    expect(new URL(await logoutUrl("unknown", jwks)).searchParams.has("id_token_hint")).toBe(false);
    expect(new URL(await logoutUrl(undefined, jwks)).searchParams.get("post_logout_redirect_uri")).toBe("http://app.test/");
  });

  it("出口へ送るとき、宛先の Host をそのまま付ける", async () => {
    const { createServer } = await import("node:http");
    const server = createServer((req, res) => res.end(JSON.stringify({ host: req.headers.host, path: req.url })));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const res = await egressFetch(`http://127.0.0.1:${port}`)("http://login.test:8081/realms/x?y=1", { method: "GET" });
    expect(await res.json()).toEqual({ host: "login.test:8081", path: "/realms/x?y=1" });
    server.close();
  });
});
