import { defineConfig } from "vitest/config";

// TypeScript の部品の単体テスト。Java と Python の単体テストは、それぞれの道具で回す（npm test）。
export default defineConfig({ test: { include: ["packages/*/test/**/*.test.ts"], testTimeout: 20_000 } });
