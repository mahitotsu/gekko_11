// テスト用の世界。認可サーバー・保険会社のシステム・事務サービス・営業 AI エージェント・顧客のアプリを実際に起動し、
// 顧客と(乗っ取られた)営業 AI エージェントを台本で動かす。
import { serve } from "@hono/node-server";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createHash, randomBytes } from "node:crypto";
import {
  INTERNAL_KEY, challengeOf, ports, urls, type Application, type InsuranceTerms, type Intent, type OfferSet,
} from "@gekko/shared";
import { createApp as createBackend } from "../../packages/insurer-backend/src/app.js";
import { resetState } from "../../packages/insurer-backend/src/state.js";
import { resetConfig as resetBackendConfig, setConfig as setBackend } from "../../packages/insurer-backend/src/config.js";
import { createApp as createMcp } from "../../packages/insurer-mcp/src/app.js";
import { setConfig as setMcp } from "../../packages/insurer-mcp/src/config.js";
import { createApp as createSales } from "../../packages/sales-agent/src/app.js";
import { config as salesConfig } from "../../packages/sales-agent/src/config.js";
import { createApp as createCustomerApp } from "../../packages/customer-app/src/app.js";
import { resetAuthState } from "../../packages/insurer-auth/src/store.js";
import { SoftAuthenticator } from "./authenticator.js";

export { setBackend, setMcp, salesConfig };

export async function startWorld() {
  process.env.INSURER_MODE_AUTH ??= "good";
  process.env.CLAUDE_CODE_OAUTH_TOKEN = ""; // テストでは本物の Claude を使わず、台本で動かす
  process.env.ANTHROPIC_API_KEY = "";
  await import("../../packages/insurer-auth/src/server.js"); // 起動する(import した時点で listen)
  const servers = [
    serve({ fetch: createBackend().fetch, port: ports.insurerBackend }),
    serve({ fetch: createMcp().fetch, port: ports.insurerMcp }),
    serve({ fetch: createSales().fetch, port: ports.salesAgent }),
    serve({ fetch: createCustomerApp().fetch, port: ports.customerApp }),
  ];
  await new Promise((r) => setTimeout(r, 300));
  return { stop: () => servers.forEach((s) => s.close()) };
}

export async function resetWorld() {
  resetState();
  resetBackendConfig();
  resetAuthState();
  setMcp({ backendAuth: "exchange", incoming: "good" });
  process.env.INSURER_MODE_AUTH = "good";
  salesConfig.tamper = false;
  await fetch(`${urls.customerApp}/api/reset`, { method: "POST" });
}

export const TERMS: InsuranceTerms[] = [{ type: "insurance_application", kinds: ["medical", "death"], maxBenefit: 10_000_000 }];

export interface OfferResult { offerJws: string; offerSet: OfferSet; offerSetId: string; nonce: string; expiresAt: number }
// 顧客が署名した一式。営業 AI エージェントと事務サービスを経由して保険会社のシステムに届く。
export interface Submission {
  offerJws: string;
  intent: Intent;
  intentAssertion: any;
  application: Application;
  assertion: any;
  insuredAssertion?: any;
}

// 顧客の側: ログイン → パスキーの登録 → 提案と申込みの許可の範囲に同意してトークンをもらう → 案を選んで署名する
export class Customer {
  cookie = "";
  auth = new SoftAuthenticator();
  constructor(readonly user: string) {}

  async login() {
    const res = await fetch(`${urls.insurerAuth}/login`, {
      method: "POST", redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ user: this.user, password: "demo", next: "/passkeys" }),
    });
    this.cookie = res.headers.get("set-cookie")!.split(";")[0]!;
    return this;
  }
  async registerSeal() {
    const h = { cookie: this.cookie, "content-type": "application/json" };
    const opt = await (await fetch(`${urls.insurerAuth}/passkeys/register/options`, { method: "POST", headers: h })).json() as { challenge: string };
    const res = await fetch(`${urls.insurerAuth}/passkeys/register/verify`, {
      method: "POST", headers: h, body: JSON.stringify(this.auth.register(opt.challenge, urls.insurerAuth)),
    });
    if (!res.ok) throw new Error(`パスキーの登録に失敗: ${await res.text()}`);
    return this;
  }
  // 認可コードフロー(PKCE + RAR)でトークンをもらう
  async tokens(terms: InsuranceTerms[] = TERMS): Promise<{ access_token: string; id_token: string }> {
    const verifier = randomBytes(32).toString("base64url");
    const redirectUri = `${urls.customerApp}/callback`;
    const form = new URLSearchParams({
      client_id: "customer-app", redirect_uri: redirectUri, state: "s",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      authorization_details: JSON.stringify(terms),
    });
    const ok = await fetch(`${urls.insurerAuth}/authorize?${form}`, { headers: { cookie: this.cookie } });
    if (!ok.ok) throw new Error("同意画面が出ません");
    const appr = await fetch(`${urls.insurerAuth}/authorize/approve`, {
      method: "POST", redirect: "manual", headers: { cookie: this.cookie, "content-type": "application/x-www-form-urlencoded" }, body: form,
    });
    const code = new URL(appr.headers.get("location")!).searchParams.get("code")!;
    const tok = await fetch(`${urls.insurerAuth}/token`, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: "customer-app", redirect_uri: redirectUri }),
    });
    return (await tok.json()) as { access_token: string; id_token: string };
  }
  async salesTicket(terms: InsuranceTerms[] = TERMS): Promise<string> {
    return (await this.tokens(terms)).access_token;
  }
  // 内容に署名する(顧客のアプリの画面でパスキーを使う操作に当たる)
  sign(content: unknown) {
    return this.auth.sign(challengeOf(content), urls.customerApp);
  }
  // 案を選んで、意向確認と申込みに署名する。
  prepare(offer: OfferResult, planId: string, opts: { insured?: Customer } = {}): Submission {
    const plan = offer.offerSet.plans.find((p) => p.id === planId)!;
    const intent: Intent = { customer: this.user, offerSetId: offer.offerSetId, planId, wish: "入院に備えたい", nonce: offer.nonce, expiresAt: offer.expiresAt };
    const intentAssertion = this.sign(intent);
    const application: Application = {
      customer: this.user, insured: opts.insured?.user ?? this.user, plan, offerSetId: offer.offerSetId,
      intentSignature: intentAssertion.response.signature, nonce: offer.nonce, expiresAt: offer.expiresAt,
    };
    return {
      offerJws: offer.offerJws, intent, intentAssertion, application, assertion: this.sign(application),
      insuredAssertion: opts.insured?.sign(application),
    };
  }
}

// 営業 AI エージェント(台本): 顧客のトークンを替えてもらい、事務サービスの MCP の道具を呼ぶ。
// 「乗っ取られた AI」を模すので、渡された値を好きなように書き換えられる。
export async function exchange(client: "sales-agent" | "insurer-mcp", subjectToken: string, audience: string, extra: Record<string, string> = {}) {
  const res = await fetch(`${urls.insurerAuth}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + Buffer.from(`${client}:${client}-secret`).toString("base64") },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", subject_token: subjectToken, audience, ...extra }),
  });
  return res.json() as Promise<{ access_token?: string; error_description?: string }>;
}

export async function connectMcp(ticket: string) {
  const client = new Client({ name: "scripted-sales-agent", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${urls.insurerMcp}/mcp`), { requestInit: { headers: { authorization: `Bearer ${ticket}` } } }));
  const call = async <T = any>(name: string, args: Record<string, unknown> = {}) => {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content as { text: string }[])[0]!.text;
    return { isError: !!r.isError, body: JSON.parse(text) as T };
  };
  return { call, close: () => client.close() };
}

export const payloadOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString());

// 認可サーバーの管理 API(営業 AI エージェントの登録の失効)
export const revokeClient = (id: string) =>
  fetch(`${urls.insurerAuth}/admin/clients/${id}/revoke`, { method: "POST", headers: { "x-internal-key": INTERNAL_KEY } });
