// 全サービスをまとめて起動する。Ctrl+C で全て止まる。
import { spawn } from "node:child_process";

const services = ["insurer-auth", "insurer-backend", "insurer-mcp", "sales-agent", "customer-app"];
const children = services.map((name) => {
  const p = spawn("npx", ["tsx", `packages/${name}/src/server.ts`], { stdio: "inherit", env: process.env });
  p.on("exit", (code) => { if (code) console.error(`[dev] ${name} が終了しました (code ${code})`); });
  return p;
});
const stop = () => children.forEach((c) => c.kill());
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
console.log("[dev] 起動しています。顧客のアプリの画面は未実装です。確認は npm test で行ってください。");
