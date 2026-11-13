// 価値を伝えるサイト（D-49）。GitHub Pages の https://mahitotsu.github.io/gekko_11/ に出す。
// 見た目は Tailwind CSS（postcss.config.mjs）で、顧客のアプリ（D-48）と同じ部品を使う。出力は静的な HTML で、JS は使わない。
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://mahitotsu.github.io",
  base: "/gekko_11",
  trailingSlash: "always",
  build: { format: "directory" },
});
