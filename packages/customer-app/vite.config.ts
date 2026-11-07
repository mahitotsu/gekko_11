// 画面のビルド。インラインのスクリプトとスタイルを作らないので、画面の CSP（D32）を 'self' だけで組める。
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: "web",
  plugins: [react()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2022",
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
