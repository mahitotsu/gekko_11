import { serve } from "@hono/node-server";
import { ports, urls } from "@gekko/shared";
import { createApp } from "./app.js";
import { hasClaude } from "./config.js";

serve({ fetch: createApp().fetch, port: ports.salesAgent }, () =>
  console.log(`[sales-agent] ${urls.salesAgent} (頭脳: ${hasClaude() ? "Claude Agent SDK" : "台本(.env に CLAUDE_CODE_OAUTH_TOKEN が無いため)"})`));
