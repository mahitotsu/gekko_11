import { defineConfig } from "vitest/config";

// クラスタのシナリオのテストと、画面のテスト。vulnerable の防御の設定を共有するので、テストファイルは並列に動かさない。
// 画面のテストのブラウザは、globalSetup が Docker で動かす（test/ui/global-setup.ts）。
export default defineConfig({
  test: {
    include: ["test/cluster/**/*.test.ts", "test/ui/**/*.test.ts"],
    globalSetup: ["test/ui/global-setup.ts"],
    fileParallelism: false,
    testTimeout: 600_000,
    hookTimeout: 600_000,
  },
});
