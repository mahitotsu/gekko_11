// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
// 事務サービス(保険会社の MCP サーバー)。営業 AI エージェントから回ってきた提出を、打ち直さずに保険会社のシステムへ通す。
import { Hono } from "hono";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import {
  actChain, audiences, bearer, emit, urls, verifyTicketGood, verifyTicketWith, VerifyError, type Ticket,
} from "@gekko/shared";
import { config } from "./config.js";
import { ticketForBackend } from "./core-ticket.js";

const actor = "事務サービス";
const mode = () => (config.backendAuth === "exchange" && config.incoming === "good" ? "good" : "bad");
const view = (t: Ticket) => ({ sub: t.sub, aud: t.aud, act: actChain(t.act), scope: t.scope, exp: t.exp });

async function verifyIncoming(token: string): Promise<Ticket> {
  return config.incoming === "good"
    ? verifyTicketGood(token, audiences.mcp)
    : verifyTicketWith(token, { signature: true, expiry: true, typ: false }); // 宛先を見ない
}

function buildServer(incoming: string, ticket: Ticket) {
  const server = new McpServer({ name: "insurer-mcp", version: "1.0.0" });
  const text = (v: unknown, isError = false) => ({ content: [{ type: "text" as const, text: JSON.stringify(v) }], isError });

  async function callBackend(action: string, path: string, init: { method: string; body?: unknown }) {
    let bt;
    try {
      bt = await ticketForBackend(incoming, ticket);
    } catch (e) {
      const msg = (e as Error).message;
      await emit({ actor, mode: mode(), action: `${action}(保険会社のシステムに出すトークンを用意できない)`, ticket: view(ticket),
        checks: [{ name: "保険会社のシステム宛てのトークンを受け取る", ok: false, detail: msg }], outcome: "rejected" });
      return text({ error: msg }, true);
    }
    const res = await fetch(`${urls.insurerBackend}${path}`, {
      method: init.method,
      headers: { authorization: `Bearer ${bt.token}`, "content-type": "application/json", "x-peer": "insurer-mcp" },
      body: init.body ? JSON.stringify(init.body) : undefined,
    });
    const json = await res.json();
    await emit({ actor, mode: mode(), action: `${action}(保険会社のシステムへ: ${bt.how})`, ticket: view(ticket),
      checks: [{ name: "保険会社のシステムの返事", ok: res.ok, detail: res.ok ? undefined : JSON.stringify(json) }], outcome: res.ok ? "ok" : "rejected" });
    return text(json, !res.ok);
  }

  // 悪い実装では「誰の契約か」を引数で受け取ってしまう。AI(またはAIを操る者)が好きな値を入れられる。
  const whoShape: Record<string, z.ZodType> = {};
  if (config.backendAuth === "client-credentials") whoShape.on_behalf_of = z.string().optional().describe("誰の契約か(顧客ID)");

  server.registerTool("get_offers", {
    description: "ログイン中の顧客に示す、複数の案の一式(保険会社が署名した提示)を取得する", inputSchema: whoShape,
  }, (args: Record<string, unknown>) =>
    callBackend("提示の取得", "/offers", { method: "POST", body: { for_user: args.on_behalf_of } }));

  server.registerTool("list_contracts", {
    description: "ログイン中の顧客の契約の一覧を照会する", inputSchema: whoShape,
  }, (args: Record<string, unknown>) =>
    callBackend("契約の照会", `/contracts${args.on_behalf_of ? `?for_user=${encodeURIComponent(String(args.on_behalf_of))}` : ""}`, { method: "GET" }));

  server.registerTool("submit_application", {
    description: "顧客が署名した意向確認と申込みを提出する",
    inputSchema: {
      offerJws: z.string().optional().describe("保険会社が署名した提示"),
      intent: z.any().describe("意向確認"), intentAssertion: z.any().optional().describe("意向確認への顧客の署名"),
      application: z.any().describe("申込み"), assertion: z.any().describe("申込みへの顧客の署名"),
      extras: z.record(z.string(), z.any()).optional().describe("その他の欄"),
    },
  }, ({ extras, ...rest }: { extras?: Record<string, unknown> } & Record<string, unknown>) =>
    callBackend("申込みの提出", "/applications", { method: "POST", body: { ...rest, ...extras } }));

  return server;
}

export function createApp() {
  const app = new Hono();
  app.all("/mcp", async (c) => {
    let token: string, ticket: Ticket;
    try {
      token = bearer(c.req.header("authorization"));
      ticket = await verifyIncoming(token);
    } catch (e) {
      const msg = e instanceof VerifyError ? e.message : (e as Error).message;
      await emit({ actor, mode: mode(), action: "トークンを受け取る", checks: [{ name: "替えたトークンの検証", ok: false, detail: msg }], outcome: "rejected" });
      return c.json({ error: msg }, 401);
    }
    await emit({ actor, mode: mode(), action: "トークンを受け取る", ticket: view(ticket),
      checks: [{ name: "署名・期限", ok: true }, { name: "宛先(aud)が MCP である", ok: true, detail: config.incoming === "good" ? undefined : "⚠ この項目は確認していません" }], outcome: "ok" });
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await buildServer(token, ticket).connect(transport);
    return transport.handleRequest(c.req.raw);
  });
  return app;
}
