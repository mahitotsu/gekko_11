import { serve } from "@hono/node-server";
import { ports, urls } from "@gekko/shared";
import { createApp } from "./app.js";

serve({ fetch: createApp().fetch, port: ports.customerApp }, () => console.log(`[customer-app] ${urls.customerApp}`));
