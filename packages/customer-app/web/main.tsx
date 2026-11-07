// 画面の入口。設定と防御の状態を読んでから、React の画面を描く。
import { createRoot } from "react-dom/client";
import { createAuth, type Config } from "./auth.ts";
import { App } from "./components/App.tsx";
import { loadDefenses } from "./defenses.ts";
import "./styles.css";

const cfg = (await (await fetch("/config.json")).json()) as Config;
const enabled = await loadDefenses();
createRoot(document.getElementById("root")!).render(<App cfg={cfg} auth={createAuth(cfg, enabled)} enabled={enabled} />);
