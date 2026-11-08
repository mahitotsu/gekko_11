// 事務サービスの MCP の道具を呼ぶ。Envoy の出口を通り、出口の token-guard が、受け口で確かめたトークンを替えて付ける。
// アプリは、受け口で受けた控えの番号（x-auth-ctx）だけを付ける。
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

export const MCP_URL = process.env.MCP_EGRESS_URL ?? "http://127.0.0.1:15102/mcp";

/** 道具の答え。保険会社のシステムの答えの JSON で、アプリが読む欄だけに型を付ける。 */
export interface ToolBody {
  error?: unknown;
  status?: number;
  contract?: { contractId?: string };
  contracts?: unknown[];
  [name: string]: unknown;
}

export interface ToolResult {
  isError: boolean;
  body: ToolBody;
}

export async function callMcp(ctx: string, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  const client = new Client({ name: "sales-agent", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(MCP_URL), { requestInit: { headers: { "x-auth-ctx": ctx } } }));
  try {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content as { text: string }[])[0]?.text ?? "{}";
    return { isError: Boolean(r.isError), body: JSON.parse(text) };
  } finally {
    await client.close();
  }
}
