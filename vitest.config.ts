import { defineConfig } from "vitest/config";

// 各サービスは固定ポートで起動するので、テストファイルは並列に動かさない。
export default defineConfig({ test: { fileParallelism: false, include: ["test/**/*.test.ts"], testTimeout: 20_000 } });
