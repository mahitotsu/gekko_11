import { serve } from "@hono/node-server";
import { createApp, engine } from "./app.ts";
import { MODEL } from "./claude.ts";
import { startAdmin } from "./tamper.ts";

serve({ fetch: createApp().fetch, hostname: "127.0.0.1", port: Number(process.env.APP_PORT ?? 8080) });
startAdmin(Number(process.env.TAMPER_ADMIN_PORT ?? 9091));
console.log(JSON.stringify({ service: "sales-agent", engine: engine(), model: engine() === "claude" ? MODEL : null }));
