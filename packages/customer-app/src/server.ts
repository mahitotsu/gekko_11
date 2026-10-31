import { serve } from "@hono/node-server";
import { createApp } from "./app.ts";

serve({ fetch: createApp().fetch, hostname: "127.0.0.1", port: Number(process.env.APP_PORT ?? 8080) });
