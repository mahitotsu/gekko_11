import { modeOf } from "@gekko/shared";

// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
// 認可サーバーの発行の仕方。悪い側は、発行側が雑だと受け取る側では防げないことを見せるための実装。
// 環境変数で選ぶ。INSURER_MODE_AUTH=bad にすると、全項目が悪い側になる。テストが切り替えるので、呼ぶたびに読む。
export interface AuthConfig {
  aud: "one" | "all"; // アクセストークンの宛先を 1 つの窓口に絞るか、全窓口にするか
  ttl: "short" | "long"; // 有効期間を短くするか、長くするか
  idTokenAud: "client" | "shared"; // ID トークンの宛先を顧客のアプリだけにするか、API の識別子まで入れるか
  act: "keep" | "drop"; // 替えるたびに経由(act)を積むか、落とすか
  terms: "narrow" | "as-requested"; // 替えるときに取決めを狭めるだけにするか、要求どおり広げるか
  target: "fixed" | "any"; // 窓口ごとに替えてよい宛先を決めるか、求められた宛先に替えるか
}

export function authConfig(): AuthConfig {
  const bad = modeOf("auth") === "bad";
  const pick = <T extends string>(name: string, good: T, badValue: T): T =>
    (process.env[`AUTH_${name}`] as T | undefined) ?? (bad ? badValue : good);
  return {
    aud: pick("AUD", "one", "all"),
    ttl: pick("TTL", "short", "long"),
    idTokenAud: pick("ID_TOKEN_AUD", "client", "shared"),
    act: pick("ACT", "keep", "drop"),
    terms: pick("TERMS", "narrow", "as-requested"),
    target: pick("EXCHANGE_TARGET", "fixed", "any"),
  };
}
