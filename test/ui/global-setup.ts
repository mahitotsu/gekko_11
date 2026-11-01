// 画面のテストのブラウザ。公式の Playwright のイメージで run-server を動かし、手元のテストは playwright-core でつなぐ（D-28）。
// ホストのネットワークを使うので、ブラウザから、k3d の入口（*.localhost:8081、8082）に届く。手元にブラウザを入れない。
import { execFileSync } from "node:child_process";
import { createConnection } from "node:net";
import { BROWSER_PORT, PLAYWRIGHT_VERSION } from "./browser.ts";

const NAME = "gekko11-browser";
const ENTRANCE_HOSTS = ["secure", "vulnerable"].flatMap((ns) => ["app", "auth", "agent"].map((name) => `${name}.${ns}.localhost`));

const open = () =>
  new Promise<boolean>((resolve) => {
    const s = createConnection(BROWSER_PORT, "127.0.0.1");
    s.on("connect", () => (s.destroy(), resolve(true)));
    s.on("error", () => resolve(false));
  });

export async function setup() {
  execFileSync("docker", ["rm", "-f", NAME], { stdio: "ignore" });
  execFileSync("docker", [
    "run", "-d", "--rm", "--name", NAME, "--network", "host", "--init",
    // npx の取り込みを、ビルドの間で使い回す
    "-v", "gekko11-npm:/root/.npm",
    // Chromium は *.localhost をループバックに解決するが、ブラウザの外（route.fetch を出す run-server）は解決しないので、入口の名前を足す
    ...ENTRANCE_HOSTS.flatMap((h) => ["--add-host", `${h}:127.0.0.1`]),
    `mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble`,
    "npx", "-y", `playwright@${PLAYWRIGHT_VERSION}`, "run-server", "--port", String(BROWSER_PORT), "--host", "127.0.0.1",
  ]);
  for (let i = 0; i < 90 && !(await open()); i++) await new Promise((r) => setTimeout(r, 1000));
  if (!(await open())) throw new Error("ブラウザの run-server が起動しない");
}

export async function teardown() {
  execFileSync("docker", ["rm", "-f", NAME], { stdio: "ignore" });
}
