import { serve } from "@hono/node-server";
import { createApp } from "./app.ts";
import { startAdmin } from "./defenses.ts";

serve({ fetch: createApp().fetch, hostname: "127.0.0.1", port: Number(process.env.APP_PORT ?? 8080) });
startAdmin(Number(process.env.APP_ADMIN_PORT ?? 9091));
