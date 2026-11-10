// Bootstrap の色のモードを、OS の設定（ライト、ダーク）に合わせる（F-G105）。インラインのスクリプトを使わないよう、ファイルで配る。
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const apply = () => document.documentElement.setAttribute("data-bs-theme", dark.matches ? "dark" : "light");
apply();
dark.addEventListener("change", apply);
