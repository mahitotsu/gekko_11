import { serve } from "@hono/node-server";
import { ports, urls } from "@gekko/shared";
import { createApp } from "./app.js";
import { config } from "./config.js";

serve({ fetch: createApp().fetch, port: ports.insurerBackend }, () =>
  console.log(`[insurer-backend] ${urls.insurerBackend} (設定: ${JSON.stringify(config)})`));
