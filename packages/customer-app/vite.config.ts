// 画面のビルド。インラインのスクリプトとスタイルを作らないので、画面の CSP（G32）を 'self' だけで組める。
// 見た目は Tailwind CSS で、使ったクラスから静的な CSS ファイルを作る（D-48）。
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: "web",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2022",
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
