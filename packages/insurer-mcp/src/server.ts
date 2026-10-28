import { serve } from "@hono/node-server";
import { ports, urls } from "@gekko/shared";
import { createApp } from "./app.js";
import { config } from "./config.js";

serve({ fetch: createApp().fetch, port: ports.insurerMcp }, () =>
  console.log(`[insurer-mcp] ${urls.insurerMcp}/mcp (事務センターの呼び方: ${config.backendAuth} / 受け取る票の宛先確認: ${config.incoming})`));
