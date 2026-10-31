import { defineConfig } from "vitest/config";

// クラスタのシナリオのテスト。vulnerable の防御の設定を共有するので、テストファイルは並列に動かさない。
export default defineConfig({
  test: { include: ["test/cluster/**/*.test.ts"], fileParallelism: false, testTimeout: 600_000, hookTimeout: 600_000 },
});
