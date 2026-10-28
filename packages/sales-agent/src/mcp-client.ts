import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { audiences, urls } from "@gekko/shared";

const basic = "Basic " + Buffer.from("sales-agent:sales-agent-secret").toString("base64");

// 顧客から受け取ったトークンを、MCP 宛てのトークンに替えてもらう。利用者本人(sub)は残り、営業員(AI)が act に記録される。
export async function ticketForMcp(customerTicket: string): Promise<string> {
  const res = await fetch(`${urls.insurerAuth}/token`, {
    method: "POST", headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: customerTicket, subject_token_type: "urn:ietf:params:oauth:token-type:access_token", audience: audiences.mcp,
    }),
  });
  const j = (await res.json()) as { access_token?: string; error_description?: string };
  if (!j.access_token) throw new Error(`替えたトークンを受け取れませんでした: ${j.error_description}`);
  return j.access_token;
}

// MCP の道具を直接呼ぶ。AI を介さない経路(提出)や、台本モードで使う。
export async function callMcp(mcpTicket: string, name: string, args: Record<string, unknown> = {}) {
  const client = new Client({ name: "sales-agent", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${urls.insurerMcp}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${mcpTicket}` } },
  }));
  try {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content as { text: string }[])[0]?.text ?? "{}";
    return { isError: Boolean(r.isError), body: JSON.parse(text) as any };
  } finally {
    await client.close();
  }
}
