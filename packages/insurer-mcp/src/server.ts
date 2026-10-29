import { serve } from "@hono/node-server";
import { ports, urls } from "@gekko/shared";
import { createApp } from "./app.js";
import { config } from "./config.js";

serve({ fetch: createApp().fetch, port: ports.insurerMcp }, () =>
  console.log(`[insurer-mcp] ${urls.insurerMcp}/mcp (保険会社のシステムの呼び方: ${config.backendAuth} / 受け取るトークンの宛先確認: ${config.incoming})`));
